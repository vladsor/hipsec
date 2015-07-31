{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}

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
import           Data.List                    (intersperse)
import           Data.Maybe
import           Data.Monoid
import           Data.Time.Clock
import qualified Data.Time.Clock              as Clock
import           Data.Time.Clock.POSIX
import           Data.Time.Format
import           Data.Time.LocalTime
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

#if MIN_VERSION_time(1,5,0)
import Data.Time.Format(defaultTimeLocale)
#else
import System.Locale (defaultTimeLocale)
#endif

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
    Just (Address proto prefixlen addr) -> showAddr addr proto prefixlen
    Nothing -> ""
  ++
  case (use_natt, natt_sport) of
    (True, Just port) -> "[" ++ show port ++ "]"
    _ -> ""
  ++ " " ++
  case daddr of
    Just (Address proto prefixlen addr) -> showAddr addr proto prefixlen
    Nothing -> ""
  ++
  case (use_natt, natt_dport) of
    (True, Just port) -> "[" ++ show port ++ "]"
    _ -> ""
  ++ " "

useNat = maybe False ((/= 0) . natttype)

dumpSA :: Msg -> UTCTime -> TimeZone -> String
dumpSA (msg@Msg{..}) ct tz  =
   pfkey_sa_dump_short msgAddressSrc (useNat msgNATTType) msgNATTSPort msgAddressDst msgNATTDPort ++
   case (msgSA, msgSA2) of
     (Nothing, Nothing) -> "No SA & SA2 extensions"
     (Just _, Nothing) -> "No SA2 extension"
     (Nothing, Just _) -> "No SA extension"
     (Just sa, Just sa2) -> pfkey_sa_dump_long msg ct tz sa sa2

pfkey_sa_dump_long :: Msg -> UTCTime -> TimeZone -> SA -> SA2 -> String
pfkey_sa_dump_long (Msg{..}) ct tz (SA{..}) (SA2{..}) =
  "\n\t" ++
  case (useNat msgNATTType, msgSatype) of
     (True, SATypeESP) -> "esp-udp"
     (True, _) -> "natt+"
     _ -> ""
  ++  show msgSatype ++ " mode=" ++ show sa2Mode ++ " " ++
  printf "spi=%u(0x%08x) reqid=%u(0x%08x)\n" saSPI saSPI sa2ReqId sa2ReqId
  ++ case (useNat msgNATTType, msgNATTOA) of
    (True, Just oa) -> "\tNAT OA=" ++ show oa ++ "\n"
    _ -> ""
  ++ case msgSatype of
    SATypeIPComp -> "\tC: " ++ show saEncrypt
    SATypeESP -> case msgKeyEncrypt of
      Nothing -> ""
      Just enc' -> "\tE: " ++ show saEncrypt ++ " " ++ show enc' ++ "\n"
    _ -> "Invalid satype"
  ++ case msgKeyAuth of
    Nothing -> ""
    Just auth' -> "\tA: " ++ show saAuth ++ " " ++ show auth' ++ "\n"
  ++
  printf "\tseq=0x%08x replay=%u flags=0x%08x " sa2Sequence saReplay saFlags
  ++ "state=" ++ show saState ++ "\n"
  ++ case msgLifetimeCurrent of
    Nothing -> ""
    Just tm ->
          let off = floor $ Clock.diffUTCTime ct (ltAddTime tm) in
          "\tcreated: " ++ strTime (ltAddTime tm) tz ++
          "\tcurrent:" ++ strTime ct tz ++ "\n" ++
          "\tdiff:" ++ (if utcTimeToPOSIXSeconds (ltAddTime tm) == 0 then "0" else
                          show off) ++ "(s)"
          ++ "\thard: " ++ maybe "0" (show . fromEnum . utcTimeToPOSIXSeconds . ltAddTime) msgLifetimeHard ++ "(s)"
          ++ "\tsoft: " ++ maybe "0" (show . fromEnum . utcTimeToPOSIXSeconds . ltAddTime) msgLifetimeSoft ++ "(s)\n"
          ++ "\tlast: " ++ strTime (ltUseTime tm) tz
          ++ "\t\t\thard: " ++ maybe "0" (show . fromEnum . utcTimeToPOSIXSeconds . ltUseTime) msgLifetimeHard ++ "(s)"
          ++ "\tsoft: " ++ maybe "0" (show . fromEnum . utcTimeToPOSIXSeconds . ltUseTime) msgLifetimeSoft ++ "(s)\n"
          ++ strLifetimeByte msgLifetimeCurrent "current"
          ++ strLifetimeByte msgLifetimeHard "hard"
          ++ strLifetimeByte msgLifetimeSoft "soft"
          ++ "\n"

          ++ "\tallocated: " ++ show (ltAllocations tm)
          ++ "\thard: " ++ maybe "0" (show . ltAllocations) msgLifetimeHard
          ++ "\tsoft: " ++ maybe "0" (show . ltAllocations) msgLifetimeSoft
          ++ "\n"

  ++ maybe "" show msgSecCtx
  ++ "\tsadb_seq=" ++ show msgSeq ++ " pid=" ++ show msgPid ++ "\n"


dumpSPD :: Msg -> TimeZone-> IO ()
dumpSPD (Msg{..}) tz = do
        when (maybe 0 policyId msgPolicy .&. 7 >= 3) $ putStr "(per-socket policy)\n"
        case (msgAddressSrc, msgAddressDst) of
            (Just (Address sproto sprefixlen saddr), Just (Address dproto dprefixlen daddr)) -> do
              sport <- case saddr of
                SockAddrInet port _ -> putStr (showAddr saddr sproto sprefixlen) >> return port
                SockAddrInet6 port _ _ _ -> putStr (showAddr saddr sproto sprefixlen) >> return port
                _ -> error "unsupported family"
              putStr " "
              dport <- case daddr of
                SockAddrInet port _ -> putStr (showAddr daddr dproto dprefixlen) >> return port
                SockAddrInet6 port _ _ _ -> putStr (showAddr daddr dproto dprefixlen) >> return port
                _ -> error "unsupported family"
              putStr " "
              let proto = if (sproto /= dproto) then error "protocol mismatched" else sproto
              putStrLn $ showProtocol proto (fromIntegral sport) (fromIntegral dport)
            _ -> error "incomplete addresses"
        putStrLn $ maybe "(none)" show msgPolicy
        putStr $ case msgLifetimeCurrent of
          Nothing -> ""
          Just tm -> "\tcreated: " ++ strTime (ltAddTime tm) tz ++ "\tlastused: " ++ strTime (ltUseTime tm) tz ++ "\n"
        putStr $ case msgLifetimeHard of
          Nothing -> ""
          Just tm -> "\tlifetime: " ++ show (fromEnum . utcTimeToPOSIXSeconds . ltAddTime $ tm) ++
                     "(s) validtime: " ++ show (fromEnum . utcTimeToPOSIXSeconds . ltUseTime $ tm) ++ "(s)\n"
        putStr $ maybe "" show msgSecCtx
        putStrLn $ "\tspid=" ++ maybe "" (show . policyId) msgPolicy ++ " seq=" ++ show msgSeq ++ " pid=" ++ show msgPid

strTime :: UTCTime -> TimeZone -> String
strTime time tz = if (utcTimeToPOSIXSeconds time == 0) then "" else formatTime defaultTimeLocale "%b %d %H:%M:%S %Y" (utcToLocalTime tz time)

strLifetimeByte :: Maybe Lifetime -> String -> String
strLifetimeByte Nothing title = "\t" ++ title ++ "0(bytes)"
strLifetimeByte (Just lt) title =
  let
    y = fromIntegral (ltBytes lt) * 1.0 :: Float
    unit = ""
    w = 0 :: Int
  in
    printf "\t%s: %.*f(%sbytes)" title w y unit

showAddr :: SockAddr -> Int -> Int -> String
showAddr addr proto prefixlen =
  show addr ++ "/" ++ show prefixlen ++
  case addr of
    SockAddrInet port _ -> if (port == aNY_PORT) then "[any]"
                           else "[" ++ show port ++ "]"
    SockAddrInet6 port _ _ _ -> if (port == aNY_PORT) then "[any]"
                                  else "[" ++ show port ++ "]"
    _ -> error "unsupported family"

showProtocol :: Int -> Int -> Int -> String
showProtocol proto sport dport =
  case unpack (fromIntegral proto) of
    Just IPProtoAny -> "any"
    Just IPProtoICMPv6 -> "icmp6" ++
      if (not (sport == iPSecPortAny) && (sport == iPSecPortAny))
      then (" " ++ show sport ++ "," ++ show dport)
      else ""
    Just IPProtoIPv4 -> "ipv4"
    Just p -> show p
    _ -> ""
