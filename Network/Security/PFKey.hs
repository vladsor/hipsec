{-# LANGUAGE EmptyDataDecls        #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies          #-}

module Network.Security.PFKey
  ( PfSocket
  , pfkey_open
  , pfkey_close
  , pfkey_recv
  , pfkey_send_flush
  , pfkey_send_dump
  , pfkey_send_promisc
  , pfkey_send_spdadd
  , pfkey_send_spddelete
  , pfkey_send_spdadd'
  , pfkey_send_add
  , pfkey_send_delete
  , pfkey_send_delete_all
  , pfkey_send_get
  , pfkey_send_register
  , pfkey_recv_register
  , pfkey_send_spdflush
  , pfkey_send_spddump
  , pfkey_sa_dump
  , pfkey_spd_dump
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
import           System.Socket                hiding (getNameInfo)
import           System.Socket.Unsafe
import           Text.Printf

mkMsg :: MsgType -> SAType -> Int -> Int -> Msg
mkMsg typ satyp seq pid =
  def { msgType = typ
      , msgSatype = satyp
      , msgSeq = seq
      }

pfkey_send_x2 :: PfSocket -> MsgType -> SAType -> Address -> Address -> Int -> IO ()
pfkey_send_x2 s typ satype src dst spi = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg typ satype 0 pid)
        { msgAddressSrc = Just src
        , msgAddressDst = Just dst
        , msgSA = Just $ SA { saSPI = spi, saReplay = 0, saState = SAStateLarval, saAuth = AuthAlgNone, saEncrypt = EncAlgNone, saFlags = 0 }
        }
  pfkey_send s msg
  return ()

pfkey_send_x3 :: PfSocket -> MsgType -> SAType -> IO ()
pfkey_send_x3 s typ satyp = case typ of
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
          let msg = mkMsg typ satyp 0 pid
          pfkey_send s msg

pfkey_send_x4 :: PfSocket -> MsgType -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> UTCTime -> UTCTime -> Policy -> Int -> IO ()
pfkey_send_x4 s typ src@(SockAddrInet _ _) prefs dst@(SockAddrInet _ _) prefd proto ltime vtime policy seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg typ SATypeUnspec 0 pid)
        { msgAddressSrc = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefs, addressAddr = src }
        , msgAddressDst = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefd, addressAddr = dst }
        , msgLifetimeHard = Just $ Lifetime { ltAllocations = 0, ltBytes = 0, ltAddTime = ltime, ltUseTime = vtime }
        , msgPolicy = Just policy
        }
  pfkey_send s msg
  return ()
pfkey_send_x4 _ _ _ _ _ _ _ _ _ _ _ = error "unsupported parameters"

pfkey_send_flush :: PfSocket -> SAType -> IO ()
pfkey_send_flush s satyp = pfkey_send_x3 s MsgTypeFlush satyp

pfkey_send_dump :: PfSocket -> SAType -> IO ()
pfkey_send_dump s satyp = pfkey_send_x3 s MsgTypeDump satyp

pfkey_send_promisc :: PfSocket -> Bool -> IO ()
pfkey_send_promisc s b = pfkey_send_x3 s MsgTypePromisc
                         (if b then SATypeUnspec1 else SATypeUnspec)

pfkey_send_spdadd :: PfSocket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
pfkey_send_spdadd s src prefs dst prefd proto policy seq =
  pfkey_send_x4 s MsgTypeSPDAdd src prefs dst prefd proto (posixSecondsToUTCTime 0) (posixSecondsToUTCTime 0) policy seq

pfkey_send_spddelete :: PfSocket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
pfkey_send_spddelete s src prefs dst prefd proto policy seq =
  pfkey_send_x4 s MsgTypeSPDDelete src prefs dst prefd proto (posixSecondsToUTCTime 0) (posixSecondsToUTCTime 0) policy seq

pfkey_send_spdadd' :: PfSocket -> SockAddr -> Int -> SockAddr -> Int -> IPProto -> Policy -> Int -> IO ()
pfkey_send_spdadd' s src@(SockAddrInet _ _) prefs dst@(SockAddrInet _ _) prefd proto policy seq = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg MsgTypeSPDAdd SATypeUnspec 0 pid)
        { msgAddressSrc = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefs, addressAddr = src }
        , msgAddressDst = Just $ Address { addressProto = fromIntegral $ pack proto, addressPrefixLen = prefd, addressAddr = dst }
        , msgPolicy = Just policy
        }
  pfkey_send s msg
  return ()
pfkey_send_spdadd' _ _ _ _ _ _ _ _ = error "invalid params"

pfkey_send_add :: PfSocket -> SAType -> IPSecMode -> Address -> Address -> Int -> Int -> Int -> AuthAlg -> Key -> EncAlg -> Key -> Int -> Maybe Lifetime -> Maybe Lifetime -> Int -> IO ()
pfkey_send_add s satyp mode src dst spi reqid reply authAlg authKey encAlg encKey flags sltm hltm seq = do
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
  pfkey_send s msg
  return ()

pfkey_send_delete :: PfSocket -> SAType -> Address -> Address -> Int -> IO ()
pfkey_send_delete s = pfkey_send_x2 s MsgTypeDelete

pfkey_send_delete_all :: PfSocket -> SAType -> Address -> Address -> IO ()
pfkey_send_delete_all s satyp src dst = do
  pid <- liftM fromIntegral getProcessID
  let msg = (mkMsg MsgTypeDelete satyp 0 pid)
        { msgAddressSrc = Just src
        , msgAddressDst = Just dst
        }
  pfkey_send s msg
  return ()

pfkey_send_get :: PfSocket -> SAType -> Address -> Address -> Int -> IO ()
pfkey_send_get s = pfkey_send_x2 s MsgTypeGet

pfkey_send_register :: PfSocket -> SAType -> IO ()
pfkey_send_register s = pfkey_send_x3 s MsgTypeRegister

pfkey_recv_register :: PfSocket -> IO (Maybe Supported, Maybe Supported)
pfkey_recv_register s = do
  msg <- pfkey_recv s
  return $ maybe (Nothing, Nothing) (\msg' -> (msgSupportedAuth msg', msgSupportedEncrypt msg')) msg

pfkey_send_spdflush :: PfSocket -> IO ()
pfkey_send_spdflush s = pfkey_send_x3 s MsgTypeSPDFlush SATypeUnspec

pfkey_send_spddump :: PfSocket -> IO ()
pfkey_send_spddump s = pfkey_send_x3 s MsgTypeSPDDump SATypeUnspec

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

pfkey_sa_dump :: Msg -> UTCTime -> String
pfkey_sa_dump msg ct =
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


pfkey_spd_dump :: Msg -> IO ()
pfkey_spd_dump msg = do
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
