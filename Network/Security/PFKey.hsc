{-# LANGUAGE CPP, MultiParamTypeClasses #-}
#include <sys/ioctl.h>

module Network.Security.PFKey where

import Network.Socket
import qualified Network.Socket.ByteString.Lazy as BS
import Network.Socket.Internal
import Network.BSD
import Network.Security.Message
import Foreign.Storable ( Storable(..) )
import Foreign.Ptr
import Foreign.Marshal.Alloc
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LBS
import Data.Binary
import System.Posix.Process
import Control.Monad
import Data.Bits
import Data.Maybe
import Data.DateTime
import Text.Printf
import qualified Data.Time.Clock as Clock
import Network.Socket.IOCtl
import System.Posix.IO.Select
import System.Posix.IO.Select.FdSet
import System.Posix.IO.Select.Types
import Foreign.C.Types
import System.Posix.Types

import Debug.Trace

_PF_KEY_V2 = 2 :: Int

pfkey_open :: IO Socket
pfkey_open = do
  s <- socket Pseudo_AF_KEY Raw (fromIntegral _PF_KEY_V2)
  setSocketOption s RecvBuffer (1024 * 1024)
  return s

pfkey_close :: Socket -> IO ()
pfkey_close = sClose

data FIONREAD = FIONREAD

instance IOControl FIONREAD CInt where
  ioctlReq _ = (#const FIONREAD) :: CInt


pfkey_recv :: Socket -> IO (Maybe Msg)
pfkey_recv s = do
  let hdrlen = (sizeOf (undefined::Msg)) :: Int
  ret <- select'' [Fd $ fdSocket s] [] [] (Time (CTimeval 10 0))
  if (ret /= 1) then return Nothing else do
  msglen <- (ioctlsocket' s FIONREAD) >>= return . fromIntegral
  if (msglen < hdrlen) then return Nothing else do
  buf <- BS.recv s (fromIntegral hdrlen)
  let hdr = decode buf
  let msglen = (msgLength hdr) `shift` 3
  buf' <- BS.recv s $ fromIntegral $ msglen - hdrlen
  if (LBS.length buf' /= fromIntegral (msglen - hdrlen)) then return Nothing else do
  return $ Just $ decode $ buf `LBS.append` buf'
    
pfkey_send :: Socket -> Msg -> IO ()
pfkey_send s msg = BS.send s (encode msg) >> return ()
  
mkMsg :: MsgType -> SAType -> Int -> Int -> Msg 
mkMsg typ satyp seq pid = defaultMsg { msgType = typ
                                     , msgSatype = satyp
                                     , msgLength = (sizeOf (undefined :: Msg)) `shiftR` 3
                                     , msgSeq = seq
                                     , msgPid = pid
				     }
                                     
{-
mkAddress :: ExtType -> SockAddr -> Int -> Int -> Address
mkAddress exttype addr prefixlen proto = Address { addressLen = (sizeOf (undefined :: Address) + sizeOfSockAddr addr) `shiftR` 3
                                                 , addressExtType = exttype
                                                 , addressProto = proto
                                                 , addressPrefixLen = prefixlen
                                                 }

-}

pfkey_send_x3 :: Socket -> MsgType -> SAType -> IO ()
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
          pid <- liftM fromIntegral $ getProcessID
          let msg = mkMsg typ satyp 0 pid
          pfkey_send s msg
    

pfkey_send_x4 :: Socket -> MsgType -> SockAddr -> Int -> SockAddr -> Int -> Int -> DateTime -> DateTime -> Policy -> Int -> IO ()
pfkey_send_x4 s typ src@(SockAddrInet _ _) prefs dst@(SockAddrInet _ _) prefd proto ltime vtime policy seq = do
  pid <- liftM fromIntegral $ getProcessID
  let msg = (mkMsg typ SATypeUnspec 0 pid) 
        { msgAddressSrc = Just $ Address { addressProto = proto, addressPrefixLen = prefs, addressAddr = src }
        , msgAddressDst = Just $ Address { addressProto = proto, addressPrefixLen = prefd, addressAddr = dst } 
        , msgLifetimeHard = Just $ Lifetime { ltAllocations = 0, ltBytes = 0, ltAddTime = ltime, ltUseTime = vtime }
        , msgPolicy = Just policy
        }
  pfkey_send s msg
  return ()
pfkey_send_x4 _ _ _ _ _ _ _ _ _ _ _ = error "unsupported parameters"

pfkey_send_flush :: Socket -> SAType -> IO ()
pfkey_send_flush s satyp = pfkey_send_x3 s MsgTypeFlush satyp

pfkey_send_dump :: Socket -> SAType -> IO ()
pfkey_send_dump s satyp = pfkey_send_x3 s MsgTypeDump satyp

pfkey_send_promisc :: Socket -> Bool -> IO ()
pfkey_send_promisc s b = pfkey_send_x3 s MsgTypePromisc 
                         (if b then SATypeUnspec1 else SATypeUnspec)

pfkey_send_spdadd :: Socket -> SockAddr -> Int -> SockAddr -> Int -> Int -> Policy -> Int -> IO ()
pfkey_send_spdadd s src prefs dst prefd proto policy seq = 
  pfkey_send_x4 s MsgTypeSPDAdd src prefs dst prefd proto startOfTime startOfTime policy seq


pfkey_send_spdflush :: Socket -> IO ()
pfkey_send_spdflush s = pfkey_send_x3 s MsgTypeSPDFlush SATypeUnspec

pfkey_send_spddump :: Socket -> IO ()
pfkey_send_spddump s = pfkey_send_x3 s MsgTypeSPDDump SATypeUnspec


iterateM_ :: (Monad m) => m Bool -> m ()
iterateM_ m = do
  r <- m
  if r then iterateM_ m else return ()

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
  
pfkey_sa_dump :: Msg -> DateTime -> String
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
        Just typ -> natttypeType typ /= 0
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
        Just typ -> natttypeType typ /= 0
  in      
  "\n\t" ++ 
  case (use_natt, satyp) of
     (True, SATypeESP) -> "esp-udp"
     (True, _) -> "natt+"
     _ -> ""
  ++  show satyp ++ show (sa2Mode sa2') ++ 
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
          "\tdiff:" ++ (if toSeconds (ltAddTime tm) == 0 then "0" else
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
          Just tm -> "\tlifetime: " ++ show (toSeconds . ltAddTime $ tm) ++ 
                     "(s) validtime: " ++ show (toSeconds . ltUseTime $ tm) ++ "(s)\n" 
        putStr $ case secctx of
          Nothing -> ""
          Just (SecCtx alg doi len ) -> "\tsecurity context doi: " ++ show doi ++ "\n" ++
                                        "\tsecurity context algorithm: " ++ show alg ++ "\n" ++
                                        "\tsecurity context length: " ++ show len ++ "\n" ++
                                        "\tsecurity context: %s\n"
        putStrLn $ "\tspid=" ++ show (policyId policy') ++ " seq=" ++ show seq ++ " pid=" ++ show pid

strTime :: DateTime -> String
strTime time = if (toSeconds time == 0) then ""
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
  case unpackIPProto (fromIntegral proto) of
    IPProtoAny -> putStr "any"
    IPProtoICMPv6 -> do
      putStr "icmp6"
      when (not (sport == iPSecPortAny) && (sport == iPSecPortAny)) 
        (putStr $ " " ++ show sport ++ "," ++ show dport)
    IPProtoIPv4 -> putStr "ipv4"
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
