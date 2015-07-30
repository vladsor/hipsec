{-# LANGUAGE RecordWildCards       #-}

module Network.Security.PFKey
  ( Socket
  , open
  , close
  , recv
  , sendFlush
  , sendDump
  , sendPromisc
  , sendSPDAdd
  , sendSPDUpdate
  , sendSPDDelete
  , sendSPDAdd'
  , sendAdd
  , sendUpdate
  , sendDelete
  , sendDeleteAll
  , sendGet
  , sendRegister
  , recvRegister
  , sendSPDFlush
  , sendSPDDump
  , dumpSA
  , dumpSPD
  ) where

import           Control.Monad
import           Data.Binary
import           Data.Bits
import qualified Data.ByteString              as BS
import qualified Data.ByteString.Lazy         as LBS
import           Data.Default
import           Data.Hex
import           Data.Maybe
import           Data.Monoid
import           Data.Time.Clock
import qualified Data.Time.Clock              as Clock
import           Data.Time.Clock.POSIX
import           Data.Time.Format
import           Debug.Trace
import           Foreign.C.Types
import           Foreign.Marshal.Alloc
import           Foreign.Ptr
import           Network.Security.Message
import           Network.Security.PFSocket
import           Network.Socket               (NameInfoFlag (..), SockAddr (..),
                                               aNY_PORT, getNameInfo)
import           System.Posix.IO.Select
import           System.Posix.IO.Select.FdSet
import           System.Posix.IO.Select.Types
import           System.Posix.Process
import           System.Posix.Types
import           Text.Printf

mkMsg :: MsgType -> SAType -> Int -> Int -> Msg
mkMsg typ satyp seq pid =
  def { msgType = typ
      , msgSatype = satyp
      , msgSeq = seq
      }

send2 :: Socket -> MsgType -> SAType -> Address -> Address -> Int -> IO ()
send2 s typ satype src dst spi = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg typ satype 0 pid)
        { msgAddressSrc = Just src
        , msgAddressDst = Just dst
        , msgSA = Just $ SA { saSPI = spi, saReplay = 0, saState = SAStateLarval, saAuth = AuthAlgNone, saEncrypt = EncAlgNone, saFlags = 0 }
        }
  void $ send s msg

send3 :: Socket -> MsgType -> SAType -> IO ()
send3 s typ satyp = case typ of
  MsgTypePromisc | satyp /= SATypeUnspec && satyp /= SATypeUnspec1 -> return ()
  MsgTypePromisc -> send'
  _ -> case satyp of
    SATypeUnspec -> send'
    SATypeAH -> send'
    SATypeESP -> send'
    SATypeIPComp -> send'
    _ -> return ()
  where send' = do
          pid <- liftM fromIntegral getProcessID
          void $ send s $ mkMsg typ satyp 0 pid

send4 :: Socket -> MsgType -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> UTCTime -> UTCTime -> Policy -> Int -> IO ()
send4 s typ src@(SockAddrInet _ _) prefs dst@(SockAddrInet _ _) prefd proto ltime vtime policy seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg typ SATypeUnspec 0 pid)
        { msgAddressSrc = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefs, addressAddr = src }
        , msgAddressDst = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefd, addressAddr = dst }
        , msgLifetimeHard = Just $ Lifetime { ltAllocations = 0, ltBytes = 0, ltAddTime = ltime, ltUseTime = vtime }
        , msgPolicy = Just policy
        }
  void $ send s msg
send4 _ _ _ _ _ _ _ _ _ _ _ = error "unsupported parameters"

sendFlush :: Socket -> SAType -> IO ()
sendFlush s = send3 s MsgTypeFlush

sendDump :: Socket -> SAType -> IO ()
sendDump s = send3 s MsgTypeDump

sendPromisc :: Socket -> Bool -> IO ()
sendPromisc s b = send3 s MsgTypePromisc $ if b then SATypeUnspec1 else SATypeUnspec

sendSPDAdd :: Socket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
sendSPDAdd s src prefs dst prefd proto policy seq =
  send4 s MsgTypeSPDAdd src prefs dst prefd proto (posixSecondsToUTCTime 0) (posixSecondsToUTCTime 0) policy seq

sendSPDUpdate :: Socket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
sendSPDUpdate s src prefs dst prefd proto policy seq =
  send4 s MsgTypeSPDUpdate src prefs dst prefd proto (posixSecondsToUTCTime 0) (posixSecondsToUTCTime 0) policy seq

sendSPDDelete :: Socket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
sendSPDDelete s src prefs dst prefd proto policy seq =
  send4 s MsgTypeSPDDelete src prefs dst prefd proto (posixSecondsToUTCTime 0) (posixSecondsToUTCTime 0) policy seq

sendSPDAdd' :: Socket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
sendSPDAdd' s src@(SockAddrInet _ _) prefs dst@(SockAddrInet _ _) prefd proto policy seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg MsgTypeSPDAdd SATypeUnspec 0 pid)
        { msgAddressSrc = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefs, addressAddr = src }
        , msgAddressDst = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefd, addressAddr = dst }
        , msgPolicy = Just policy
        }
  void $ send s msg
sendSPDAdd' _ _ _ _ _ _ _ _ = error "invalid params"

sendAdd :: Socket -> SAType -> IPSecMode -> Address -> Address -> Int -> Int -> Int -> AuthAlg -> Key -> EncAlg -> Key -> Int -> Maybe Lifetime -> Maybe Lifetime -> Int -> IO ()
sendAdd s satyp mode src dst spi reqid reply authAlg authKey encAlg encKey flags sltm hltm seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg MsgTypeAdd satyp seq pid)
        { msgAddressSrc = Just src
        , msgAddressDst = Just dst
        , msgSA = Just $ SA { saSPI = spi, saReplay = reply, saState = SAStateLarval, saAuth = authAlg, saEncrypt = encAlg, saFlags = flags }
        , msgSA2 = Just $ SA2 { sa2Mode = mode, sa2Sequence = 0, sa2ReqId = reqid }
        , msgKeyAuth = Just authKey
        , msgKeyEncrypt = Just encKey
        , msgLifetimeHard = hltm
        , msgLifetimeSoft = sltm
        }
  void $ send s msg

sendUpdate :: Socket -> SAType -> IPSecMode -> Address -> Address -> Int -> Int -> Int -> AuthAlg -> Key -> EncAlg -> Key -> Int -> Maybe Lifetime -> Maybe Lifetime -> Int -> IO ()
sendUpdate s satyp mode src dst spi reqid reply authAlg authKey encAlg encKey flags sltm hltm seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg MsgTypeUpdate satyp seq pid)
        { msgAddressSrc = Just src
        , msgAddressDst = Just dst
        , msgSA = Just $ SA { saSPI = spi, saReplay = reply, saState = SAStateLarval, saAuth = authAlg, saEncrypt = encAlg, saFlags = flags }
        , msgSA2 = Just $ SA2 { sa2Mode = mode, sa2Sequence = 0, sa2ReqId = reqid }
        , msgKeyAuth = Just authKey
        , msgKeyEncrypt = Just encKey
        , msgLifetimeHard = hltm
        , msgLifetimeSoft = sltm
        }
  void $ send s msg

sendDelete :: Socket -> SAType -> Address -> Address -> Int -> IO ()
sendDelete s = send2 s MsgTypeDelete

grepSPI :: Socket -> SAType -> [Address] -> [Address] -> IO [Int]
grepSPI s satyp srcs dsts = send3 s MsgTypeDump satyp >> go []
  where
    go acc = do
      res <- recv s
      case res of
        Nothing -> return acc
        Just (Msg{..}) | msgType /= MsgTypeDump -> return acc
        Just (Msg{..}) | msgErrno /= 0 -> return acc
        Just (Msg{..}) | msgSatype /= satyp -> go acc
        Just (Msg{..}) -> (\acc' -> if msgSeq /= 0 then go acc' else return acc') $ fromMaybe acc $ do
          src <- msgAddressSrc
          dst <- msgAddressDst
          sa <- msgSA
          if (any (== src) srcs) && (any (== dst) dsts) then Just (acc ++ [saSPI sa]) else Nothing


sendDeleteAll :: Socket -> SAType -> Address -> Address -> IO ()
sendDeleteAll s satyp src dst = do
  mapM_ (sendDelete s satyp src dst) =<< (grepSPI s satyp [src] [dst])

sendGet :: Socket -> SAType -> Address -> Address -> Int -> IO ()
sendGet s = send2 s MsgTypeGet

sendRegister :: Socket -> SAType -> IO ()
sendRegister s = send3 s MsgTypeRegister

recvRegister :: Socket -> IO (Maybe Supported, Maybe Supported)
recvRegister s = do
  msg <- recv s
  return $ maybe (Nothing, Nothing) (\msg' -> (msgSupportedAuth msg', msgSupportedEncrypt msg')) msg

sendSPDFlush :: Socket -> IO ()
sendSPDFlush s = send3 s MsgTypeSPDFlush SATypeUnspec

sendSPDDump :: Socket -> IO ()
sendSPDDump s = send3 s MsgTypeSPDDump SATypeUnspec

pfkey_sa_dump_short saddr use_natt natt_sport daddr natt_dport =
  case saddr of
    Just (Address proto prefixlen addr) -> showAddr' addr proto prefixlen
    Nothing -> ""
  ++
  case (use_natt, natt_sport) of
    (True, Just port) -> "[" ++ show port ++ "]"
    _ -> ""
  ++ " " ++
  case daddr of
    Just (Address proto prefixlen addr) -> showAddr' addr proto prefixlen
    Nothing -> ""
  ++
  case (use_natt, natt_dport) of
    (True, Just port) -> "[" ++ show port ++ "]"
    _ -> ""
  ++ " "

dumpSA :: Msg -> UTCTime -> String
dumpSA msg ct =
  let sa = msgSA msg
      sa2 = msgSA2 msg
      saddr = msgAddressSrc msg
      daddr = msgAddressDst msg
      natt_type = msgNATTType msg
      natt_sport = msgNATTSPort msg
      natt_dport = msgNATTDPort msg
      use_natt = case natt_type of
        Nothing -> False
        Just typ -> natttype typ /= 0
  in
   pfkey_sa_dump_short saddr use_natt natt_sport daddr natt_dport ++
   case (sa, sa2) of
     (Nothing, Nothing) -> "No SA & SA2 extensions"
     (Just _, Nothing) -> "No SA2 extension"
     (Nothing, Just _) -> "No SA extension"
     (Just sa', Just sa2') ->  pfkey_sa_dump_long msg ct sa' sa2'

pfkey_sa_dump_long msg ct sa' sa2' =
  let lftc = msgLifetimeCurrent msg
      lfth = msgLifetimeHard msg
      lfts = msgLifetimeSoft msg
      saddr = msgAddressSrc msg
      daddr = msgAddressDst msg
      paddr = msgAddressProxy msg
      auth = msgKeyAuth msg
      enc = msgKeyEncrypt msg
      sid = msgIdentitySrc msg
      did = msgIdentityDst msg
      sens = msgSensitivity msg
      sec_ctx = msgSecCtx msg
      natt_type = msgNATTType msg
      natt_oa = msgNATTOA msg
      seq = msgSeq msg
      pid = msgPid msg
      satyp = msgSatype msg
      secctx = msgSecCtx msg
      use_natt = case natt_type of
        Nothing -> False
        Just typ -> natttype typ /= 0
  in
  "\n\t" ++
  case (use_natt, satyp) of
     (True, SATypeESP) -> "esp-udp"
     (True, _) -> "natt+"
     _ -> ""
  ++  show satyp ++ " mode=" ++ show (sa2Mode sa2') ++ " " ++
  printf "spi=%u(0x%08x) reqid=%u(0x%08x)\n" (saSPI sa') (saSPI sa') (sa2ReqId sa2') (sa2ReqId sa2')
  ++ case (use_natt, natt_oa) of
    (True, Just oa) -> "\tNAT OA=" ++ show oa ++ "\n"
    _ -> ""
  ++ case satyp of
    SATypeIPComp -> "\tC: " ++ show (saEncrypt sa')
    SATypeESP -> case enc of
      Nothing -> ""
      Just enc' -> "\tE: " ++ show (saEncrypt sa') ++ " " ++ show enc' ++ "\n"
    _ -> "Invalid satype"
  ++ case auth of
    Nothing -> ""
    Just auth' -> "\tA: " ++ show (saAuth sa') ++ " " ++ show auth' ++ "\n"
  ++
  printf "\tseq=0x%08x replay=%u flags=0x%08x " (sa2Sequence sa2') (saReplay sa') (saFlags sa')
  ++ "state=" ++ show (saState sa') ++ "\n"
  ++ case lftc of
    Nothing -> ""
    Just tm ->
          let off = Clock.diffUTCTime ct (ltAddTime tm) in
          "\tcreated: " ++ strTime (ltAddTime tm) ++
          "\tcurrent:" ++ (show ct) ++ "\n" ++
          "\tdiff:" ++ (if utcTimeToPOSIXSeconds (ltAddTime tm) == 0 then "0" else
                          show off) ++ "(s)"
          ++ "\thard: " ++ fromMaybe "0" (fmap (show . ltAddTime) lfth) ++ "(s)"
          ++ "\tsoft: " ++ fromMaybe "0" (fmap (show . ltAddTime) lfts) ++ "(s)\n"
          ++ "\tlast: " ++ strTime (ltUseTime tm)
          ++ "\thard: " ++ fromMaybe "0" (fmap (show . ltUseTime) lfth) ++ "(s)"
          ++ "\tsoft: " ++ fromMaybe "0" (fmap (show . ltUseTime) lfts) ++ "(s)\n"
          ++ strLifetimeByte lftc "current"
          ++ strLifetimeByte lfth "hard"
          ++ strLifetimeByte lfts "soft"
          ++ "\n"

          ++ "\tallocated: " ++ show (ltAllocations tm)
          ++ "\thard: " ++ fromMaybe "0" (fmap (show . ltAllocations) lfth)
          ++ "\tsoft: " ++ fromMaybe "0" (fmap (show . ltAllocations) lfts)
          ++ "\n"

  ++ case secctx of
    Nothing -> ""
    Just (SecCtx alg doi len ) -> "\tsecurity context doi: " ++ show doi ++ "\n" ++
                                      "\tsecurity context algorithm: " ++ show alg ++ "\n" ++
                                      "\tsecurity context length: " ++ show len ++ "\n" ++
                                      "\tsecurity context: %s\n"

  ++ "\tsadb_seq=" ++ show seq ++ " pid=" ++ show pid ++ "\n"


dumpSPD :: Msg -> IO ()
dumpSPD msg = do
        let saddr = msgAddressSrc msg
            daddr = msgAddressDst msg
            policy = msgPolicy msg
            lftc = msgLifetimeCurrent msg
            lfth = msgLifetimeHard msg
            secctx = msgSecCtx msg
            seq = msgSeq msg
            pid = msgPid msg
            policy' = case policy of
              Nothing -> error ""
              Just p -> p
        when (policyId policy' .&. 7 >= 3) $ putStr "(per-socket policy)\n"
        case (saddr, daddr) of
            (Just (Address sproto sprefixlen saddr), Just (Address dproto dprefixlen daddr)) -> do
              sport <- case saddr of
                SockAddrInet port _ -> showAddr saddr sproto sprefixlen >> return port
                SockAddrInet6 port _ _ _ -> showAddr saddr sproto sprefixlen >> return port
                _ -> error "unsupported family"
              putStr " "
              dport <- case daddr of
                SockAddrInet port _ -> showAddr daddr dproto dprefixlen >> return port
                SockAddrInet6 port _ _ _ -> showAddr daddr dproto dprefixlen >> return port
                _ -> error "unsupported family"
              putStr " "
              let proto = if (sproto /= dproto) then error "protocol mismatched" else sproto
              showProtocol proto (fromIntegral sport) (fromIntegral dport)
              putStr "\n"
            _ -> error "incomplete addresses"
        putStr "\tPolicy: "
        ipsec_dump_policy policy'
        putStr $ case lftc of
          Nothing -> ""
          Just tm -> "\tcreated: " ++ strTime (ltAddTime tm) ++ " lastused: " ++ strTime (ltUseTime tm) ++ "\n"
        putStr $ case lfth of
          Nothing -> ""
          Just tm -> "\tlifetime: " ++ show (utcTimeToPOSIXSeconds . ltAddTime $ tm) ++
                     "(s) validtime: " ++ show (utcTimeToPOSIXSeconds . ltUseTime $ tm) ++ "(s)\n"
        putStr $ case secctx of
          Nothing -> ""
          Just (SecCtx alg doi len ) -> "\tsecurity context doi: " ++ show doi ++ "\n" ++
                                        "\tsecurity context algorithm: " ++ show alg ++ "\n" ++
                                        "\tsecurity context length: " ++ show len ++ "\n" ++
                                        "\tsecurity context: %s\n"
        putStrLn $ "\tspid=" ++ show (policyId policy') ++ " seq=" ++ show seq ++ " pid=" ++ show pid

strTime :: UTCTime -> String
strTime time = if (utcTimeToPOSIXSeconds time == 0) then ""
               else show time

strLifetimeByte :: Maybe Lifetime -> String -> String
strLifetimeByte Nothing title = "\t" ++ title ++ "0(bytes)"
strLifetimeByte (Just lt) title =
  let
    y = fromIntegral (ltBytes lt) * 1.0 :: Float
    unit = ""
    w = 0 :: Int
  in
    printf "\t%s: %.*f(%sbytes)" title w y unit

showAddr :: SockAddr -> Int -> Int -> IO ()
showAddr addr proto prefixlen = do
  (hostName, _) <- getNameInfo [NI_NUMERICHOST] True False addr
  putStr $ fromMaybe "" hostName
  putStr $ "/" ++ show prefixlen
  case addr of
    SockAddrInet port _ -> if (port == aNY_PORT) then putStr "[any]"
                           else putStr $ "[" ++ show port ++ "]"
    SockAddrInet6 port _ _ _ -> if (port == aNY_PORT) then print "[any]"
                                  else putStr $ "[" ++ show port ++ "]"
    _ -> error "unsupported family"

showAddr' :: SockAddr -> Int -> Int -> String
showAddr' addr proto prefixlen =
  show addr ++ "/" ++ show prefixlen ++
  case addr of
    SockAddrInet port _ -> if (port == aNY_PORT) then "[any]"
                           else "[" ++ show port ++ "]"
    SockAddrInet6 port _ _ _ -> if (port == aNY_PORT) then "[any]"
                                  else "[" ++ show port ++ "]"
    _ -> error "unsupported family"

showProtocol :: Int -> Int -> Int -> IO ()
showProtocol proto sport dport =
  case unpack (fromIntegral proto) of
    Just IPProtoAny -> putStr "any"
    Just IPProtoICMPv6 -> do
      putStr "icmp6"
      when (not (sport == iPSecPortAny) && (sport == iPSecPortAny))
        (putStr $ " " ++ show sport ++ "," ++ show dport)
    Just IPProtoIPv4 -> putStr "ipv4"
    p -> putStr $ show p

priorityLow =     0xC0000000
priorityDefault = 0x80000000
priorityHigh    = 0x40000000

ipsec_dump_policy :: Policy -> IO ()
ipsec_dump_policy (Policy typ dir id prio reqs) = do
  let (str, off) = if (prio == 0) then ("" , 0)
                else if (prio < (priorityDefault `shiftR` 2) * 3) then ("prio high", prio - priorityHigh)
                     else if (prio < (priorityDefault `shiftR` 2) * 5) then ("prio def", prio - priorityDefault)
                          else ("prio low", prio - priorityDefault)
      (off', operator) = if (off > 0) then (off * (-1), "-") else (off, "+")
  if off /= 0 then do
    putStr $ show dir ++ " " ++ str ++ "" ++ operator ++ " " ++ show off ++ " " ++ show typ
    else if str /= "" then do
                           putStr $ show dir ++ " " ++ str ++ " " ++ show typ
         else do
              putStr $ show dir ++ " " ++ show typ
  putStr "\n"
  if (typ /= IPSecPolicyIPSec) then return () else do
    sequence_ $ fmap ipsec_dump_ipsecrequest reqs

iPSecManualReqidMax = 0x3fff

ipsec_dump_ipsecrequest :: IPSecRequest -> IO ()
ipsec_dump_ipsecrequest (IPSecRequest proto mode level 0 Nothing) =
  putStrLn $ show proto ++ "/" ++ show mode ++ "//" ++ show level
ipsec_dump_ipsecrequest (IPSecRequest proto mode level reqid Nothing) =
  let ch = if (reqid > iPSecManualReqidMax) then '#' else ':'
  in
   putStrLn $ show proto ++ "/" ++ show mode ++ "//" ++ show level ++ [ch] ++ show reqid
ipsec_dump_ipsecrequest (IPSecRequest proto mode level 0 (Just (addr1, addr2))) =
  putStrLn $ show proto ++ "/" ++ show mode ++ "/" ++ show addr1 ++ "-" ++ show addr2 ++ "/" ++ show level
ipsec_dump_ipsecrequest (IPSecRequest proto mode level reqid (Just (addr1, addr2))) =
  let ch = if (reqid > iPSecManualReqidMax) then '#' else ':'
  in
   putStrLn $ show proto ++ "/" ++ show mode ++ "/" ++ show addr1 ++ "-" ++ show addr2 ++ "/" ++ show level ++ [ch] ++ show reqid
