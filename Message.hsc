{-# LANGUAGE CPP #-}

#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <netinet/in.h>

module Message (
  Msg(..)
  , MsgType(..)
  , Address(..)
  , Policy(..)
  , IPSecRequest(..)
  , IPSecPolicy(..)
  , Lifetime(..)
  , SecCtx(..)
  , NATTType(..)
  , SA (..)
  , SA2 (..)  
  , packMsgType
  , unpackMsgType
  , SAType(..)
  , packSAType
  , unpackSAType
    
  , iPSecPortAny
--  , iPSecUlprotoAny
--  , iPSecProtoAny
--  , iPProtoICMPv6
--  , iPProtoIPv4
  , IPProto(..)
  , packIPProto
  , unpackIPProto
    
  , IPSecDir
  , IPSecMode
  , IPSecLevel
  , defaultMsg
  ) where
  
import Foreign.Storable ( Storable(..) )
import qualified Data.ByteString.Lazy as LBS
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Foreign.C.Types ( CInt, CUInt, CChar, CSize )
import Control.Monad (liftM)
import Debug.Trace
import Data.Bits
import Control.Monad
import Data.DateTime
import Network.Socket
import Network.Socket.Internal
import qualified Control.Monad.State as St
import Data.Maybe

data Msg = Msg 
  { msgVersion :: Int
  , msgType :: MsgType
  , msgErrno :: Int
  , msgSatype :: SAType
  , msgLength :: Int
  , msgSeq :: Int
  , msgPid :: Int
--  , msgBody :: ByteString
  , msgSA :: Maybe SA
  , msgLifetimeCurrent :: Maybe Lifetime
  , msgLifetimeHard :: Maybe Lifetime
  , msgLifetimeSoft :: Maybe Lifetime
  , msgAddressSrc :: Maybe Address
  , msgAddressDst :: Maybe Address
  , msgAddressProxy :: Maybe Address
  , msgKeyAuth :: Maybe Key
  , msgKeyEncrypt :: Maybe Key
  , msgIdentitySrc :: Maybe Identity
  , msgIdentityDst :: Maybe Identity
  , msgSensitivity :: Maybe Sensitivity
  , msgProposal :: Maybe Proposal
  , msgSupportedAuth :: Maybe Supported
  , msgSupportedEncrypt :: Maybe Supported
  , msgSPIRange :: Maybe SPIRange
  , msgKMPrivate :: Maybe KMPrivate
  , msgPolicy :: Maybe Policy
  , msgSA2 :: Maybe SA2
  , msgNATTType :: Maybe NATTType
  , msgNATTSPort :: Maybe NATTPort
  , msgNATTDPort :: Maybe NATTPort
  , msgNATTOA :: Maybe Address
  , msgSecCtx :: Maybe SecCtx
  , msgKMAddress :: Maybe KMAddress
  } deriving (Show, Eq)

defaultMsg :: Msg
defaultMsg = Msg { msgVersion = #const PF_KEY_V2
                 , msgType = MsgTypeReserved
                 , msgErrno = 0
                 , msgSatype = SATypeUnspec
                 , msgLength = 0
                 , msgSeq = 0
                 , msgPid = 0
                 , msgSA = Nothing
                 , msgLifetimeCurrent = Nothing
                 , msgLifetimeHard = Nothing
                 , msgLifetimeSoft = Nothing
                 , msgAddressSrc = Nothing
                 , msgAddressDst = Nothing
                 , msgAddressProxy = Nothing
                 , msgKeyAuth = Nothing
                 , msgKeyEncrypt = Nothing
                 , msgIdentitySrc = Nothing
                 , msgIdentityDst = Nothing
                 , msgSensitivity = Nothing
                 , msgProposal = Nothing
                 , msgSupportedAuth = Nothing
                 , msgSupportedEncrypt = Nothing
                 , msgSPIRange = Nothing
                 , msgKMPrivate = Nothing
                 , msgPolicy = Nothing
                 , msgSA2 = Nothing
                 , msgNATTType = Nothing
                 , msgNATTSPort = Nothing
                 , msgNATTDPort = Nothing
                 , msgNATTOA = Nothing
                 , msgSecCtx = Nothing
                 , msgKMAddress = Nothing
                 }

iPSecPortAny :: Int
iPSecPortAny = #const IPSEC_PORT_ANY

--iPSecUlprotoAny :: Int
--iPSecUlprotoAny = #const IPSEC_ULPROTO_ANY

--iPSecProtoAny :: Int
--iPSecProtoAny = #const IPSEC_PROTO_ANY

--iPProtoICMPv6 :: Int
--iPProtoICMPv6 = #const IPPROTO_ICMPV6
--iPProtoIPv4 :: Int
--iPProtoIPv4 = #const IPPROTO_IPIP

data IPProto = IPProtoAny
             | IPProtoESP
             | IPProtoAH
             | IPProtoIPComp
             | IPProtoIPIP
             | IPProtoIPv4
             | IPProtoICMPv6
             | IPProtoICMP
             | IPProtoUnknown Int

instance Show IPProto where
  show IPProtoAny = "any"
  show IPProtoESP = "esp"
  show IPProtoAH = "ah"
  show IPProtoIPComp = "ipcomp"
  show IPProtoIPIP = "ipip"
  show IPProtoIPv4 = "ipv4"
  show IPProtoICMPv6 = "ipv6-icmp"
  show IPProtoICMP = "icmp"
  show (IPProtoUnknown v) = show v

instance Read IPProto where
  readsPrec _ = 
    tryParse
    [ ("any", IPProtoAny)
    , ("esp", IPProtoESP)
    , ("ah", IPProtoAH)
    , ("ipcomp", IPProtoIPComp)
    , ("ipip", IPProtoIPIP)
    , ("ipv4", IPProtoIPv4)
    , ("ipv6-icmp", IPProtoICMPv6)
    , ("icmp", IPProtoICMP)
    ]

packIPProto :: IPProto -> CInt
packIPProto p = case p of
  IPProtoAny -> 255
  IPProtoESP -> 50
  IPProtoAH -> 51
  IPProtoIPComp -> 108
  IPProtoIPIP -> 94
  IPProtoIPv4 -> 94
  IPProtoICMPv6 -> 58
  IPProtoICMP -> 1
  IPProtoUnknown v -> fromIntegral v

unpackIPProto :: CInt -> IPProto
unpackIPProto p = case p of
  255 -> IPProtoAny
  50 -> IPProtoESP
  51 -> IPProtoAH
  108 -> IPProtoIPComp
  94 -> IPProtoIPIP
  58 -> IPProtoICMPv6
  1 -> IPProtoICMP
  v -> IPProtoUnknown $ fromIntegral v


repeateL :: (Monad m) => (Int, a) -> ((Int, a) -> m (Int, a)) -> m a
repeateL (l, a) f = do
  if (l > 0) then do
    (l', a') <- f (l, a)
    repeateL (l', a') f
    else return a

#let alignment t = "%lu", (unsigned long)offsetof(struct {char x__; t (y__);}, y__)
instance Storable Msg where
   alignment _ = #{alignment struct sadb_msg}
   sizeOf _ = #{size struct sadb_msg}
   peek ptr = undefined {-do
     version <- #{peek struct sadb_msg, sadb_msg_version} ptr :: IO Word8
     typ <- #{peek struct sadb_msg, sadb_msg_type} ptr :: IO Word8
     errno <- #{peek struct sadb_msg, sadb_msg_errno} ptr :: IO Word8
     satype <- liftM unpackSAType $ #{peek struct sadb_msg, sadb_msg_satype} ptr
     length <- #{peek struct sadb_msg, sadb_msg_len} ptr
     seq <- #{peek struct sadb_msg, sadb_msg_seq} ptr
     pid <- #{peek struct sadb_msg, sadb_msg_pid} ptr
     return (SADB_msg 
             (fromIntegral version) (unpackMsgType $ fromIntegral (typ :: Int)) errno satype length seq pid empty)-}
   poke = undefined {-ptr (Msg version typ errno satype length seq pid body) = do
     #{poke struct sadb_msg, sadb_msg_version} ptr version
     #{poke struct sadb_msg, sadb_msg_type} ptr $ packMsgType typ     
     #{poke struct sadb_msg, sadb_msg_errno} ptr errno 
     #{poke struct sadb_msg, sadb_msg_satype} ptr $ packSAType satype 
     #{poke struct sadb_msg, sadb_msg_len} ptr length
     #{poke struct sadb_msg, sadb_msg_reserved} ptr (0::Int)
     #{poke struct sadb_msg, sadb_msg_seq} ptr seq 
     #{poke struct sadb_msg, sadb_msg_pid} ptr pid 
      -}
instance Binary Msg where
   put msg@(Msg version typ errno satype length seq pid _  _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ ) = do
     putWord8 $ fromIntegral version
     putWord8 $ fromIntegral $ packMsgType typ
     putWord8 $ fromIntegral errno
     putWord8 $ fromIntegral $ packSAType satype
     putWord16le $ fromIntegral $ msgLength' msg
     putWord16le 0
     putWord32le $ fromIntegral seq
     putWord32le $ fromIntegral pid
     
     put $ msgSA msg >>= return . (\a -> SA_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeSA)) a)
     put $ msgLifetimeCurrent msg >>= return . 
       (\a -> Lifetime_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeLifetimeCurrent)) a)
     put $ msgLifetimeHard msg >>= return . 
       (\a -> Lifetime_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeLifetimeHard)) a)
     put $ msgLifetimeSoft msg >>= return . 
       (\a -> Lifetime_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeLifetimeSoft)) a)
     put $ msgAddressSrc msg >>= return . 
       (\a -> Address_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeAddressSrc)) a)
     put $ msgAddressDst msg >>= return . 
       (\a -> Address_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeAddressDst)) a)
     put $ msgAddressProxy msg >>= return . 
       (\a -> Address_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeAddressProxy)) a)
     put $ msgKeyAuth msg >>= return . 
       (\a -> Key_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeKeyAuth)) a)
     put $ msgKeyEncrypt msg >>= return . 
       (\a -> Key_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeKeyEncrypt)) a)
     put $ msgIdentitySrc msg
     put $ msgIdentityDst msg
     put $ msgSensitivity msg
     put $ msgProposal msg
     put $ msgSupportedAuth msg
     put $ msgSupportedEncrypt msg
     put $ msgSPIRange msg
     put $ msgKMPrivate msg
     put $ msgPolicy msg >>= return . 
       (\a -> Policy_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypePolicy)) a)
     put $ msgSA2 msg
     put $ msgNATTType msg
     put $ msgNATTSPort msg
     put $ msgNATTDPort msg
     put $ msgNATTOA msg >>= return . 
       (\a -> Address_ (ExtHdr (sizeOf a) (fromIntegral $ packExtType ExtTypeNATTOA)) a)
     put $ msgSecCtx msg
     put $ msgKMAddress msg
   
   get = do
     version <- getWord8
     typ <- getWord8
     errno <- getWord8
     satype <- getWord8
     len <- getWord16le
     _ <- getWord16le
     seq <- getWord32le
     pid <- getWord32le
     let hdr = Msg { msgVersion = fromIntegral version
                  , msgType = unpackMsgType $ fromIntegral typ
                  , msgErrno = fromIntegral errno
                  , msgSatype = unpackSAType $ fromIntegral satype
                  , msgLength = fromIntegral len
                  , msgSeq = fromIntegral seq
                  , msgPid = fromIntegral pid
--                  , msgBody = body
                  , msgSA = Nothing
                  , msgLifetimeCurrent = Nothing
                  , msgLifetimeHard = Nothing
                  , msgLifetimeSoft = Nothing
                  , msgAddressSrc = Nothing
                  , msgAddressDst = Nothing
                  , msgAddressProxy = Nothing
                  , msgKeyAuth = Nothing
                  , msgKeyEncrypt = Nothing
                  , msgIdentitySrc = Nothing
                  , msgIdentityDst = Nothing
                  , msgSensitivity = Nothing
                  , msgProposal = Nothing
                  , msgSupportedAuth = Nothing
                  , msgSupportedEncrypt = Nothing
                  , msgSPIRange = Nothing
                  , msgKMPrivate = Nothing
                  , msgPolicy = Nothing
                  , msgSA2 = Nothing
                  , msgNATTType = Nothing
                  , msgNATTSPort = Nothing
                  , msgNATTDPort = Nothing
                  , msgNATTOA = Nothing
                  , msgSecCtx = Nothing
                  , msgKMAddress = Nothing
                  }
     let bodylen = fromIntegral (((fromIntegral len) :: Int) * 8 -  #{size struct sadb_msg})
     
--     trace (show hdr) $ 
     if bodylen > 0 then do
       buf <- uncheckedLookAhead bodylen 
       if (LBS.length buf /= bodylen) then return hdr
         else do
         repeateL (fromIntegral bodylen, hdr) updateMsgCnt
       else
       return hdr
     

updateMsgCnt :: (Int, Msg) -> Get (Int, Msg)
updateMsgCnt (left, msg) = do
  hdr <- uncheckedLookAhead 4
  let (extlen, exttype) = flip runGet hdr (do
                                              len <- getWord16le 
                                              typ <- getWord16le
                                              return (len, typ))
--  let len = (fromIntegral extlen) `shift` 3 - 4
  let left' = left - ((fromIntegral extlen) `shift` 3)
  --trace ("len=" ++ show extlen ++ ", type=" ++ show (unpackExtType (fromIntegral exttype))) $ 
  case unpackExtType (fromIntegral exttype) of
    ExtTypeReserved -> do
      ext <- get :: Get Ext
      trace ("res" ++ show ext ) $ return (left', msg)
    ExtTypeSA -> do
      sa <- get :: Get SA_
      return (left', msg { msgSA = Just $ sa_Cnt sa})
    ExtTypeLifetimeCurrent -> do
      lt <- get :: Get Lifetime_
      return (left', msg { msgLifetimeCurrent = Just $ lifetime_Cnt lt })
    ExtTypeLifetimeHard -> do
      lt <- get :: Get Lifetime_
      return (left', msg { msgLifetimeHard = Just $ lifetime_Cnt lt })
    ExtTypeLifetimeSoft ->  do
      lt <- get :: Get Lifetime_
      return (left', msg { msgLifetimeSoft = Just $ lifetime_Cnt lt })
    ExtTypeAddressSrc -> do
      addr <- get :: Get Address_
      return (left', msg { msgAddressSrc = Just $ address_Cnt addr })
    ExtTypeAddressDst -> do
      addr <- get :: Get Address_
      return (left', msg { msgAddressDst = Just $ address_Cnt addr })
    ExtTypeAddressProxy -> do
      addr <- get :: Get Address_
      return (left', msg { msgAddressProxy = Just $ address_Cnt addr })
    ExtTypeKeyAuth -> do
      key <- get :: Get Key_
      return (left', msg { msgKeyAuth = Just $ key_Cnt key })
    ExtTypeKeyEncrypt -> do
      key <- get :: Get Key_
      return (left', msg { msgKeyEncrypt = Just $ key_Cnt key })
    ExtTypeIdentitySrc -> do
      ident <- get :: Get Identity
      return (left', msg { msgIdentitySrc = Just ident })
    ExtTypeIdentityDst -> do
      ident <- get :: Get Identity
      return (left', msg { msgIdentityDst = Just ident })
    ExtTypeSensitivity -> do
      sens <- get :: Get Sensitivity
      return (left', msg { msgSensitivity = Just sens })
    ExtTypeProposal -> do
      prop <- get :: Get Proposal
      return (left', msg { msgProposal = Just prop })
    ExtTypeSupportedAuth -> do
      supp <- get :: Get Supported
      return (left', msg { msgSupportedAuth = Just supp })
    ExtTypeSupportedEncrypt -> do
      supp <- get :: Get Supported
      return (left', msg { msgSupportedEncrypt = Just supp })
    ExtTypeSPIRange -> do
      range <- get :: Get SPIRange
      return (left', msg { msgSPIRange = Just range })
    ExtTypeKMPrivate -> do
      kmp <- get :: Get KMPrivate
      return (left', msg { msgKMPrivate = Just kmp })
    ExtTypePolicy -> do
      policy <- get :: Get Policy_
      return (left', msg { msgPolicy = Just $ policy_Cnt policy })
    ExtTypeSA2 -> do
      sa2 <- get :: Get SA2
      return (left', msg { msgSA2 = Just sa2 })
    ExtTypeNATTType -> do
      typ <- get :: Get NATTType
      return (left', msg { msgNATTType = Just typ })
    ExtTypeNATTSPort -> do
      port <- get :: Get NATTPort
      return (left', msg { msgNATTSPort = Just port })
    ExtTypeNATTDPort -> do
      port <- get :: Get NATTPort
      return (left', msg { msgNATTDPort = Just port })
    ExtTypeNATTOA -> do
      addr <- get :: Get Address_
      return (left', msg { msgNATTOA = Just $ address_Cnt addr })
    ExtTypeSecCtx -> do
      ctx <- get :: Get SecCtx
      return (left', msg { msgSecCtx = Just ctx })
    ExtTypeKMAddress -> do
      kmaddr <- get :: Get KMAddress
      return (left', msg { msgKMAddress = Just kmaddr })
--    t -> error $ "type: " ++ show t

class Length a where
  lengthOf :: a -> Int
  
msgLength' :: Msg -> Int
msgLength' msg = flip shiftR 3 $ flip St.execState #{size struct sadb_msg} $ do
  let 
    mlen :: (Storable a) => Maybe a -> Int
    mlen = fromMaybe 0 . fmap sizeOf
    inc a = do 
      v <- St.get
      St.put (v + a)
      return v
  inc $ mlen $ msgSA msg
  inc $ mlen $ msgLifetimeCurrent msg
  inc $ mlen $ msgLifetimeHard msg
  inc $ mlen $ msgLifetimeSoft msg
  inc $ mlen $ msgAddressSrc msg
  inc $ mlen $ msgAddressDst msg
  inc $ mlen $ msgAddressProxy msg
  inc $ mlen $ msgKeyAuth msg
  inc $ mlen $ msgKeyEncrypt msg
  inc $ mlen $ msgIdentitySrc msg
  inc $ mlen $ msgIdentityDst msg
  inc $ mlen $ msgSensitivity msg
  inc $ mlen $ msgProposal msg
  inc $ mlen $ msgSupportedAuth msg
  inc $ mlen $ msgSupportedEncrypt msg
  inc $ mlen $ msgSPIRange msg
  inc $ mlen $ msgKMPrivate msg
  inc $ mlen $ msgPolicy msg
  inc $ mlen $ msgSA2 msg
  inc $ mlen $ msgNATTType msg
  inc $ mlen $ msgNATTSPort msg
  inc $ mlen $ msgNATTDPort msg
  inc $ mlen $ msgNATTOA msg
  inc $ mlen $ msgSecCtx msg
  inc $ mlen $ msgKMAddress msg
  return 0

data MsgType = MsgTypeReserved
             | MsgTypeGetSPI
             | MsgTypeUpdate
             | MsgTypeAdd
             | MsgTypeDelete
             | MsgTypeGet
             | MsgTypeAcquire
             | MsgTypeRegister           
             | MsgTypeExpire             
             | MsgTypeFlush
             | MsgTypeDump              
             | MsgTypePromisc
             | MsgTypePChange
             | MsgTypeSPDUpdate
             | MsgTypeSPDAdd           
             | MsgTypeSPDDelete
             | MsgTypeSPDGet           
             | MsgTypeSPDAcquire
             | MsgTypeSPDDump          
             | MsgTypeSPDFlush         
             | MsgTypeSPDSetidx
             | MsgTypeSPDExpire
             | MsgTypeSPDDelete2
             | MsgTypeNATTNewMapping
             | MsgTypeMigrate          
             deriving (Show, Eq)

packMsgType :: MsgType -> CInt
packMsgType t = case t of
  MsgTypeReserved -> #const SADB_RESERVED
  MsgTypeGetSPI -> #const SADB_GETSPI
  MsgTypeUpdate -> #const SADB_UPDATE
  MsgTypeAdd -> #const SADB_ADD
  MsgTypeDelete -> #const SADB_DELETE
  MsgTypeGet -> #const SADB_GET
  MsgTypeAcquire -> #const SADB_ACQUIRE
  MsgTypeRegister -> #const SADB_REGISTER           
  MsgTypeExpire -> #const SADB_EXPIRE             
  MsgTypeFlush -> #const SADB_FLUSH
  MsgTypeDump -> #const SADB_DUMP              
  MsgTypePromisc -> #const SADB_X_PROMISC
  MsgTypePChange -> #const SADB_X_PCHANGE
  MsgTypeSPDUpdate -> #const SADB_X_SPDUPDATE
  MsgTypeSPDAdd -> #const SADB_X_SPDADD           
  MsgTypeSPDDelete -> #const SADB_X_SPDDELETE
  MsgTypeSPDGet -> #const SADB_X_SPDGET          
  MsgTypeSPDAcquire -> #const SADB_X_SPDACQUIRE
  MsgTypeSPDDump -> #const SADB_X_SPDDUMP          
  MsgTypeSPDFlush -> #const SADB_X_SPDFLUSH         
  MsgTypeSPDSetidx -> #const SADB_X_SPDSETIDX
  MsgTypeSPDExpire -> #const SADB_X_SPDEXPIRE
  MsgTypeSPDDelete2 -> #const SADB_X_SPDDELETE2
  MsgTypeNATTNewMapping -> #const SADB_X_NAT_T_NEW_MAPPING
  MsgTypeMigrate -> #const SADB_X_MIGRATE          

unpackMsgType :: CInt -> MsgType
unpackMsgType t = case t of
  (#const SADB_RESERVED) -> MsgTypeReserved
  (#const SADB_GETSPI) -> MsgTypeGetSPI
  (#const SADB_UPDATE) -> MsgTypeUpdate
  (#const SADB_ADD) -> MsgTypeAdd
  (#const SADB_DELETE) -> MsgTypeDelete
  (#const SADB_GET) -> MsgTypeGet
  (#const SADB_ACQUIRE) -> MsgTypeAcquire
  (#const SADB_REGISTER) -> MsgTypeRegister
  (#const SADB_EXPIRE) -> MsgTypeExpire
  (#const SADB_FLUSH) -> MsgTypeFlush
  (#const SADB_DUMP) -> MsgTypeDump
  (#const SADB_X_PROMISC) -> MsgTypePromisc
  (#const SADB_X_PCHANGE) -> MsgTypePChange
  (#const SADB_X_SPDUPDATE) -> MsgTypeSPDUpdate
  (#const SADB_X_SPDADD) -> MsgTypeSPDAdd
  (#const SADB_X_SPDDELETE) -> MsgTypeSPDDelete
  (#const SADB_X_SPDGET) -> MsgTypeSPDGet
  (#const SADB_X_SPDACQUIRE) -> MsgTypeSPDAcquire
  (#const SADB_X_SPDDUMP) -> MsgTypeSPDDump
  (#const SADB_X_SPDFLUSH) -> MsgTypeSPDFlush
  (#const SADB_X_SPDSETIDX) -> MsgTypeSPDSetidx
  (#const SADB_X_SPDEXPIRE) -> MsgTypeSPDExpire
  (#const SADB_X_SPDDELETE2) -> MsgTypeSPDDelete2
  (#const SADB_X_NAT_T_NEW_MAPPING) -> MsgTypeNATTNewMapping
  (#const SADB_X_MIGRATE) -> MsgTypeMigrate
  _ -> error $ "unknown type: " ++ show t 

data SAType = SATypeUnspec
            | SATypeUnspec1 
            | SATypeAH
            | SATypeESP
            | SATypeRSVP
            | SATypeOSPFv2
            | SATypeRIPv2
            | SATypeMIP
            | SATypeIPComp
            deriving (Show, Eq)
                     
packSAType :: SAType -> CInt
packSAType t = case t of
  SATypeUnspec -> #const SADB_SATYPE_UNSPEC
  SATypeUnspec1 -> 1
  SATypeAH -> #const SADB_SATYPE_AH
  SATypeESP -> #const SADB_SATYPE_ESP
  SATypeRSVP -> #const SADB_SATYPE_RSVP
  SATypeOSPFv2 -> #const SADB_SATYPE_OSPFV2
  SATypeRIPv2 -> #const SADB_SATYPE_RIPV2
  SATypeMIP -> #const SADB_SATYPE_MIP
  SATypeIPComp -> #const SADB_X_SATYPE_IPCOMP

unpackSAType :: CInt -> SAType
unpackSAType t = case t of
  (#const SADB_SATYPE_UNSPEC) -> SATypeUnspec
  1 -> SATypeUnspec1
  (#const SADB_SATYPE_AH) -> SATypeAH
  (#const SADB_SATYPE_ESP) -> SATypeESP
  (#const SADB_SATYPE_RSVP) -> SATypeRSVP
  (#const SADB_SATYPE_OSPFV2) -> SATypeOSPFv2
  (#const SADB_SATYPE_RIPV2) -> SATypeRIPv2
  (#const SADB_SATYPE_MIP) -> SATypeMIP
  (#const SADB_X_SATYPE_IPCOMP) -> SATypeIPComp

data ExtHdr = ExtHdr { exthdrLen :: Int
                     , exthdrType :: Int
                     } deriving (Show, Eq)

instance Storable ExtHdr where
   alignment _ = #{alignment struct sadb_ext}
   sizeOf _ = #{size struct sadb_ext}  

instance Binary ExtHdr where
  put (ExtHdr len typ) = do
    putWord16le $ fromIntegral len
    putWord16le $ fromIntegral typ
  get = do
    len <- getWord16le
    typ <- getWord16le
    return $ ExtHdr { exthdrLen = fromIntegral len
                    , exthdrType = fromIntegral typ
                    }

data Ext = Ext { extLen :: Int
               , extType :: Int
               , extData :: LBS.ByteString
               } deriving (Show, Eq)

instance Storable Ext where
   alignment _ = #{alignment struct sadb_ext}
   sizeOf _ = #{size struct sadb_ext}  

instance Binary Ext where
  put (Ext len typ dat) = do
    putWord16le $ fromIntegral len
    putWord16le $ fromIntegral typ
    putLazyByteString dat
  get = do
    len <- getWord16le
    typ <- getWord16le
    dat <- getLazyByteString $ fromIntegral $ (len `shift` 3 - #{size struct sadb_ext})
    return $ Ext { extLen = fromIntegral len
                 , extType = fromIntegral typ
                 , extData = dat
                 }

data SAState = SAStateLarval 
             | SAStateMature
             | SAStateDying
             | SAStateDead
               deriving (Eq)

instance Show SAState where 
  show SAStateLarval = "larval"
  show SAStateMature = "mature"
  show SAStateDying = "dying"
  show SAStateDead = "dead"

packSAState :: SAState -> CInt
packSAState t = case t of
  SAStateLarval -> #const SADB_SASTATE_LARVAL
  SAStateMature -> #const SADB_SASTATE_MATURE
  SAStateDying -> #const SADB_SASTATE_DYING
  SAStateDead -> #const SADB_SASTATE_DEAD

unpackSAState :: CInt -> SAState
unpackSAState t = case t of
  (#const SADB_SASTATE_LARVAL) -> SAStateLarval
  (#const SADB_SASTATE_MATURE) -> SAStateMature
  (#const SADB_SASTATE_DYING) -> SAStateDying
  (#const SADB_SASTATE_DEAD) -> SAStateDead

data SA = SA { saSPI :: Int
             , saReplay :: Int
             , saState :: SAState
             , saAuth :: AuthAlg
             , saEncrypt :: EncAlg
             , saFlags :: Int 
             } deriving (Show, Eq)

instance Storable SA where
   alignment _ = #{alignment struct sadb_sa}
   sizeOf _ = #{size struct sadb_sa}  

instance Length SA where
   lengthOf a = #{size struct sadb_sa}  

data SA_ = SA_ { sa_Hdr :: ExtHdr, sa_Cnt :: SA }
  
instance Binary SA_ where
  put (SA_ hdr (SA spi replay state auth encrypt flags)) = do
    put hdr
    putWord32be $ fromIntegral spi
    putWord8 $ fromIntegral replay
    putWord8 $ fromIntegral $ packSAState state
    putWord8 $ fromIntegral $ packAuthAlg auth
    putWord8 $ fromIntegral $ packEncAlg encrypt
    putWord32le $ fromIntegral flags
  get = do
    hdr <- get
    spi <- getWord32be
    replay <- getWord8
    state <- getWord8
    auth <- getWord8
    encrypt <- getWord8
    flags <- getWord32le
    return $ SA_ hdr (SA { saSPI = fromIntegral spi
                , saReplay = fromIntegral replay
                , saState = unpackSAState $ fromIntegral state
                , saAuth = unpackAuthAlg $ fromIntegral auth
                , saEncrypt = unpackEncAlg $ fromIntegral encrypt
                , saFlags = fromIntegral flags
                })

data Lifetime = Lifetime { ltAllocations :: Int
                         , ltBytes :: Int
                         , ltAddTime :: DateTime
                         , ltUseTime :: DateTime
                         } deriving (Show, Eq)
                
instance Storable Lifetime where
   alignment _ = #{alignment struct sadb_lifetime}
   sizeOf _ = #{size struct sadb_lifetime}  
instance Length Lifetime where
   lengthOf a = #{size struct sadb_lifetime}  

data Lifetime_ = Lifetime_ { lifetime_Hdr :: ExtHdr, lifetime_Cnt :: Lifetime }

instance Binary Lifetime_ where
  put (Lifetime_ hdr (Lifetime allocations bytes addtime usetime)) = do
    put hdr
    putWord32le $ fromIntegral allocations
    putWord64le $ fromIntegral bytes
    putWord64le $ fromIntegral $ toSeconds addtime
    putWord64le $ fromIntegral $ toSeconds usetime
  get = do
    hdr <- get
    allocations <- getWord32le
    bytes <- getWord64le
    addtime <- getWord64le
    usetime <- getWord64le
    return $ Lifetime_ hdr (Lifetime { ltAllocations = fromIntegral allocations
                                     , ltBytes = fromIntegral bytes
                                     , ltAddTime = fromSeconds $ fromIntegral addtime
                                     , ltUseTime = fromSeconds $ fromIntegral usetime
                                     })

data Address = Address { addressProto :: Int
                       , addressPrefixLen :: Int
                       , addressAddr :: SockAddr
                       } deriving (Show, Eq)
               
data Address_ = Address_ { address_Hdr :: ExtHdr, address_Cnt :: Address }

instance Storable Address where
   alignment _ = #{alignment struct sadb_address}
   sizeOf _ = #{size struct sadb_address}  

instance Length Address where
   lengthOf a = #{size struct sadb_address}  

instance Binary Address_ where
  put (Address_ hdr (Address proto prefixlen addr)) = do
    let addrlen = case addr of
          SockAddrInet6 _ _ _ _ -> 24
          SockAddrInet _ _ -> 16
    put $ hdr { exthdrLen =  #{size struct sadb_address} + addrlen }
    putWord8 $ fromIntegral proto
    putWord8 $ fromIntegral prefixlen
    putWord16le 0
    case addr of
      SockAddrInet6 (PortNum port) flowinfo (ha0, ha1, ha2, ha3) scopeid -> do
        putWord16le $ fromIntegral $ packFamily AF_INET6
        putWord16le port
        putWord32be flowinfo
        putWord32be ha0
        putWord32be ha1
        putWord32be ha2
        putWord32be ha3
        putWord32le scopeid
        putWord16le 0
      SockAddrInet (PortNum port) inet -> do
        putWord16le $ fromIntegral $ packFamily AF_INET
        putWord16le port
        putWord32le inet
        putWord64le 0
      _ -> error "unsupported family"

  get = do
    hdr <- get
    proto <- getWord8
    prefixlen <- getWord8
    _ <- getWord16le
    family <- getWord16le >>= return . unpackFamily . fromIntegral
    let left = exthdrLen hdr `shift` 3 - #{size struct sadb_address}
    let addrSize = sizeOfSockAddrByFamily family
    if (left /= addrSize) then error "invalid addr"
      else do
      addr <- case family of
        AF_INET6 -> do
          port <- getWord16le
          flowinfo <- getWord32be
          ha0 <- getWord32be 
          ha1 <- getWord32be
          ha2 <- getWord32be
          ha3 <- getWord32be
          scopeid <- getWord32le
          _ <- getByteString $ left - 22
          return $ SockAddrInet6 (PortNum port) flowinfo (ha0, ha1, ha2, ha3) scopeid
        AF_INET -> do
          port <- getWord16le
          inet <- getWord32le
          _ <- getByteString $ left - 8
          return $ SockAddrInet (PortNum port) inet
        _ -> error "unsupported family"
      return $ Address_ hdr (Address { addressProto = fromIntegral proto
                                     , addressPrefixLen = fromIntegral prefixlen
                                     , addressAddr = addr
                                     })

instance Binary SockAddr where
  put addr = do
    case addr of
      SockAddrInet6 (PortNum port) flowinfo (ha0, ha1, ha2, ha3) scopeid -> do
        putWord16le $ fromIntegral $ packFamily AF_INET6
        putWord16le port
        putWord32be flowinfo
        putWord32be ha0
        putWord32be ha1
        putWord32be ha2
        putWord32be ha3
        putWord32le scopeid
        putWord16le 0
      SockAddrInet (PortNum port) inet -> do
        putWord16le $ fromIntegral $ packFamily AF_INET
        putWord16le port
        putWord32le inet
        putWord64le 0
      _ -> error "unsupported family"

  get = do
    family <- getWord16le >>= return . unpackFamily . fromIntegral
    addr <- case family of
      AF_INET6 -> do
        port <- getWord16le
        flowinfo <- getWord32be
        ha0 <- getWord32be 
        ha1 <- getWord32be
        ha2 <- getWord32be
        ha3 <- getWord32be
        scopeid <- getWord32le
        _ <- getByteString 8
        return $ SockAddrInet6 (PortNum port) flowinfo (ha0, ha1, ha2, ha3) scopeid
      AF_INET -> do
        port <- getWord16le
        inet <- getWord32le
        _ <- getByteString 8
        return $ SockAddrInet (PortNum port) inet
      _ -> error $ "unsupported family:" ++ show family
    return addr

data Key = Key { keyBits :: Int
               , keyData :: LBS.ByteString
               } deriving (Show, Eq)
           
instance Storable Key where
   alignment _ = #{alignment struct sadb_key}
   sizeOf _ = #{size struct sadb_key}  

instance Length Key where
   lengthOf a = #{size struct sadb_key}  

data Key_ = Key_ { key_Hdr :: ExtHdr, key_Cnt :: Key }

instance Binary Key_ where
  put (Key_ hdr (Key bits dat)) = do
    put hdr
    putWord16le $ fromIntegral bits
    putWord16le 0
  get = do
    before <- bytesRead
    hdr <- get
    bits <- getWord16le
    _ <- getWord16le
    let left =  fromIntegral $ (exthdrLen hdr) `shiftL` 3 - #{size struct sadb_key}
    if (bits > left * 8) then error ("invalid len for key" ++ show bits) else do
      dat <- getLazyByteString $ fromIntegral $ bits `shiftR` 3
      let padlen = left - bits `shiftR` 3
      _ <- getLazyByteString $ fromIntegral padlen
      after <- bytesRead
      if (after - before /= fromIntegral (exthdrLen hdr) `shiftL` 3) then error $ "invalid len:" ++ (show (after - before)) else
        return $ Key_ hdr (Key { keyBits = fromIntegral bits, keyData = dat})

data Identity = Identity { identType :: Int
                         , identId :: Int
                         } deriving (Show, Eq)

instance Storable Identity where
   alignment _ = #{alignment struct sadb_ident}
   sizeOf _ = #{size struct sadb_ident}  

instance Length Identity where
   lengthOf a = #{size struct sadb_ident}  

instance Binary Identity where
  put (Identity typ id) = do
    putWord16le $ fromIntegral typ
    putWord16le 0
    putWord64le $ fromIntegral id
  get = do
    typ <- getWord16le
    _ <- getWord16le
    id <- getWord64le
    return $ Identity { identType = fromIntegral typ
                      , identId = fromIntegral id
                      }
  
data Sensitivity = Sensitivity { sensDpd :: Int
                               , sensLevel :: Int
                               , sensLen :: Int
                               , sensIntegLevel :: Int
                               , sensIntegLen :: Int
                               , sensBitmap :: Int
                               , sensIntegBitmap :: Int
                               } deriving (Show, Eq)

instance Storable Sensitivity where
   alignment _ = #{alignment struct sadb_sens}
   sizeOf _ = #{size struct sadb_sens}  

instance Length Sensitivity where
   lengthOf a = #{size struct sadb_sens}  

instance Binary Sensitivity where
  put (Sensitivity dpd level len integLevel integLen bitmap integBitmap) = do
    putWord32le $ fromIntegral dpd
    putWord8 $ fromIntegral level
    putWord8 $ fromIntegral len
    putWord8 $ fromIntegral integLevel
    putWord8 $ fromIntegral integLen
    putWord32le 0
  get = do
    dpd <- getWord32le
    level <- getWord8
    len <- getWord8
    integLevel <- getWord8
    integLen <- getWord8
    _ <- getWord32le
    return $ Sensitivity { sensDpd = fromIntegral dpd
                         , sensLevel = fromIntegral level
                         , sensLen = fromIntegral len
                         , sensIntegLevel = fromIntegral integLevel
                         , sensIntegLen = fromIntegral integLen
                         , sensBitmap = 0
                         , sensIntegBitmap = 0
                         }

data Proposal = Proposal { propReplay :: Int
                         , propCombs :: [Combs]
                         } deriving (Show, Eq)

instance Storable Proposal where
   alignment _ = #{alignment struct sadb_prop}
   sizeOf _ = #{size struct sadb_prop}  

instance Binary Proposal where
  put (Proposal replay combs) = do
    putWord8 $ fromIntegral replay
    putWord8 0
    putWord8 0
    putWord8 0
  get = do
    replay <- getWord8
    _ <- getWord8
    _ <- getWord8
    _ <- getWord8
    return $ Proposal { propReplay = fromIntegral replay
                      , propCombs = []
                      }

data Combs = Combs { combAuth :: Int
                   , combEncrypt :: Int
                   , combFlags :: Int
                   , combAuthMinBits :: Int
                   , combAuthMaxBits :: Int
                   , combEncryptMinBits :: Int
                   , combEncryptMaxBits :: Int
                   , combSoftAllocations :: Int
                   , combHardAllocations :: Int
                   , combSoftBytes :: Int
                   , combHardBytes :: Int
                   , combSoftAddTime :: Int
                   , combHardAddTime :: Int
                   , combSoftUseTime :: Int
                   , combHardUseTime :: Int
                   } deriving (Show, Eq)

data Supported = Supported { supportedAlgs :: [Alg] } deriving (Show, Eq)

instance Storable Supported where
   alignment _ = #{alignment struct sadb_supported}
   sizeOf _ = #{size struct sadb_supported}  

instance Binary Supported where
  put (Supported algs) = do
    putWord32le 0
  get = do
    _ <- getWord32le
    return $ Supported { supportedAlgs = []
                       }

data Alg = Alg { algId :: Int
               , algIvLen :: Int
               , algMinBits :: Int
               , algMaxBits :: Int
               } deriving (Show, Eq)

data SPIRange = SPIRange { spirangeMin :: Int
                         , spirangeMax :: Int
                         } deriving (Show, Eq)

instance Storable SPIRange where
   alignment _ = #{alignment struct sadb_spirange}
   sizeOf _ = #{size struct sadb_spirange}  

instance Binary SPIRange where
  put (SPIRange min max) = do
    putWord32le $ fromIntegral min
    putWord32le $ fromIntegral max
    putWord32le 0
  get = do
    min <- getWord32le
    max <- getWord32le
    _ <- getWord32le
    return $ SPIRange { spirangeMin = fromIntegral min
                      , spirangeMax = fromIntegral max
                      }
      
data KMPrivate = KMPrivate deriving (Show, Eq)

instance Storable KMPrivate where
   alignment _ = #{alignment struct sadb_x_kmprivate}
   sizeOf _ = #{size struct sadb_x_kmprivate}  

instance Binary KMPrivate where
  put _ = do
    putWord32le 0
  get = do
    _ <- getWord32le
    return KMPrivate

data SA2 = SA2 { sa2Mode :: IPSecMode
               , sa2Sequence :: Int
               , sa2ReqId :: Int
               } deriving (Show, Eq)

instance Storable SA2 where
   alignment _ = #{alignment struct sadb_x_sa2}
   sizeOf _ = #{size struct sadb_x_sa2}  

instance Binary SA2 where
  put (SA2 mode seq reqid) = do
    putWord8 $ fromIntegral $ packIPSecMode mode
    putWord8 0
    putWord16le 0
    putWord32le $ fromIntegral seq
    putWord32le $ fromIntegral reqid
  get = do
    mode <- getWord8 >>= return . unpackIPSecMode . fromIntegral
    _ <- getWord8
    _ <- getWord16le
    seq <- getWord32le
    reqid <- getWord32le
    return $ SA2 { sa2Mode = mode
                 , sa2Sequence = fromIntegral seq
                 , sa2ReqId = fromIntegral reqid
                 }


data Policy = Policy { policyType :: IPSecPolicy
                     , policyDir :: IPSecDir
                     , policyId :: Int
                     , policyPriority :: Int
--                     , policyData :: LBS.ByteString
                     , policyIPSecRequests :: [IPSecRequest]
                     } deriving (Show, Eq)

instance Storable Policy where
   alignment _ = #{alignment struct sadb_x_policy}
   sizeOf p = #{size struct sadb_x_policy} + 
              #{size struct sadb_x_ipsecrequest} * length (policyIPSecRequests p)

data Policy_ = Policy_ { policy_Hdr :: ExtHdr, policy_Cnt :: Policy }

instance Binary Policy_ where
  put (Policy_ hdr (Policy typ dir id prio reqs)) = do
    put hdr
    putWord16le $ fromIntegral $ packIPSecPolicy typ
    putWord8 $ fromIntegral $ packIPSecDir dir
    putWord8 0
    putWord32le $ fromIntegral id
    putWord32le $ fromIntegral prio
    mapM_ put reqs
  get = do
    hdr <- get
    let left = exthdrLen hdr `shiftL` 3 - #{size struct sadb_x_policy}
    typ <- getWord16le >>= return . unpackIPSecPolicy . fromIntegral
    dir <- getWord8 >>= return . unpackIPSecDir . fromIntegral
    _ <- getWord8
    id <- getWord32le
    prio <- getWord32le
    reqs <- readArray left get
    return $ Policy_ hdr (Policy { policyType = typ
                                 , policyDir = dir
                                 , policyId = fromIntegral id
                                 , policyPriority = fromIntegral prio
                                 , policyIPSecRequests = reqs
                                 })

readArray :: Int -> Get a -> Get [a]
readArray left f = do
  if (left == 0) then return [] 
    else do
    off <- bytesRead >>= return . fromIntegral
    a <- f
    off' <- bytesRead >>= return . fromIntegral
    as <- (readArray (left + off - off') f)
    return $ a : as
  
data IPSecRequest = IPSecRequest { ipsecreqProto :: Int
                                 , ipsecreqMode :: IPSecMode
                                 , ipsecreqLevel :: IPSecLevel
                                 , ipsecreqReqId :: Int
                                 , ipsecreqAddrs :: Maybe (SockAddr, SockAddr)
                                 } deriving (Show, Eq)

instance Binary IPSecRequest where
  put (IPSecRequest proto mode level reqid Nothing) = do
    putWord16le $ #{size struct sadb_x_ipsecrequest}
    putWord16le $ fromIntegral proto
    putWord8 $ fromIntegral $ packIPSecMode mode 
    putWord8 $ fromIntegral $ packIPSecLevel level
    putWord16le 0
    putWord32le $ fromIntegral reqid
    putWord32le 0
  put (IPSecRequest proto mode level reqid (Just (saddr, daddr))) = do
    putWord16le $ #{size struct sadb_x_ipsecrequest}
    putWord16le $ fromIntegral proto
    putWord8 $ fromIntegral $ packIPSecMode mode 
    putWord8 $ fromIntegral $ packIPSecLevel level
    putWord16le 0
    putWord32le $ fromIntegral reqid
    putWord32le 0
    put saddr
    put daddr
  get = do
    len <- getWord16le -- >>= return . fromIntegral
--    trace ("ipsec len=" ++ show len) $ if ((len `shiftL` 3) /= #{size struct sadb_x_ipsecrequest}) then error "ipsecreq invalid len" else do
    proto <- getWord16le
    mode <- getWord8 >>= return . unpackIPSecMode . fromIntegral
    level <- getWord8 >>= return . unpackIPSecLevel . fromIntegral
    _ <- getWord16le
    reqid <- getWord32le
    _ <- getWord32le
    let left = len - #{size struct sadb_x_ipsecrequest}
    trace ("left=" ++ show left) $ return undefined
    addrs <- if left == 0 then return Nothing
             else do
               addr1 <- get
               addr2 <- get
               return $ Just (addr1, addr2)
    return $ IPSecRequest { ipsecreqProto = fromIntegral proto
                          , ipsecreqMode = mode
                          , ipsecreqLevel = level
                          , ipsecreqReqId = fromIntegral reqid
                          , ipsecreqAddrs = addrs
                          }

data IPSecMode = IPSecModeAny
               | IPSecModeTransport
               | IPSecModeTunnel
               | IPSecModeBeet
               deriving (Eq)

instance Show IPSecMode where 
  show IPSecModeAny = "any"
  show IPSecModeTransport = "transport"
  show IPSecModeTunnel = "tunnel"
  show IPSecModeBeet = "beet"

instance Read IPSecMode where
  readsPrec _ = 
    tryParse
    [ ("any", IPSecModeAny)
    , ("transport", IPSecModeTransport)
    , ("tunnel", IPSecModeTunnel)
    , ("beet", IPSecModeTunnel)
    ]

packIPSecMode :: IPSecMode -> CInt
packIPSecMode t = case t of
  IPSecModeAny -> #const IPSEC_MODE_ANY
  IPSecModeTransport -> #const IPSEC_MODE_TRANSPORT
  IPSecModeTunnel -> #const IPSEC_MODE_TUNNEL
  IPSecModeBeet -> #const IPSEC_MODE_BEET
  
unpackIPSecMode :: CInt -> IPSecMode
unpackIPSecMode t = case t of
  (#const IPSEC_MODE_ANY) -> IPSecModeAny
  (#const IPSEC_MODE_TRANSPORT) -> IPSecModeTransport
  (#const IPSEC_MODE_TUNNEL) -> IPSecModeTunnel
  (#const IPSEC_MODE_BEET) -> IPSecModeBeet
  
data IPSecDir = IPSecDirAny
              | IPSecDirInbound
              | IPSecDirOutbound
              | IPSecDirForward
              | IPSecDirMax
              | IPSecDirInvalid
              deriving (Eq)

instance Show IPSecDir where 
  show IPSecDirAny = "any"
  show IPSecDirInbound = "in"
  show IPSecDirOutbound = "out"
  show IPSecDirForward = "fwd"
  show IPSecDirMax = "max"
  show IPSecDirInvalid = "invalid"
  
instance Read IPSecDir where
  readsPrec _ = 
    tryParse
    [ ("any", IPSecDirAny)
    , ("in", IPSecDirInbound)
    , ("out", IPSecDirOutbound)
    , ("fwd", IPSecDirForward)
    , ("max", IPSecDirMax)
    , ("invalid", IPSecDirInvalid)
    ]

tryParse [] _ = [] 
tryParse ((attempt, result):xs) value =
  if (take (length attempt) value) == attempt
  then [(result, drop (length attempt) value)]
  else tryParse xs value
  
packIPSecDir :: IPSecDir -> CInt
packIPSecDir t = case t of
  IPSecDirAny -> #const IPSEC_DIR_ANY
  IPSecDirInbound -> #const IPSEC_DIR_INBOUND
  IPSecDirOutbound -> #const IPSEC_DIR_OUTBOUND
  IPSecDirForward -> #const IPSEC_DIR_FWD
  IPSecDirMax -> #const IPSEC_DIR_MAX
  IPSecDirInvalid -> #const IPSEC_DIR_INVALID
  
unpackIPSecDir :: CInt -> IPSecDir
unpackIPSecDir t = case t of
  (#const IPSEC_DIR_ANY) -> IPSecDirAny
  (#const IPSEC_DIR_INBOUND) -> IPSecDirInbound
  (#const IPSEC_DIR_OUTBOUND) -> IPSecDirOutbound
  (#const IPSEC_DIR_FWD) -> IPSecDirForward
  (#const IPSEC_DIR_MAX) -> IPSecDirMax
  (#const IPSEC_DIR_INVALID) -> IPSecDirInvalid

data IPSecPolicy = IPSecPolicyDiscard
                 | IPSecPolicyNone
                 | IPSecPolicyIPSec
                 | IPSecPolicyEntrust
                 | IPSecPolicyBypass
                 deriving (Eq)

instance Show IPSecPolicy where
  show IPSecPolicyDiscard = "discard"
  show IPSecPolicyNone = "none"
  show IPSecPolicyIPSec = "ipsec"
  show IPSecPolicyEntrust = "entrust"
  show IPSecPolicyBypass = "bypass"
  
instance Read IPSecPolicy where
  readsPrec _ = 
    tryParse
    [ ("discard", IPSecPolicyDiscard)
    , ("none", IPSecPolicyNone)
    , ("ipsec", IPSecPolicyIPSec)
    , ("entrust", IPSecPolicyEntrust)
    , ("bypass", IPSecPolicyBypass)
    ]

packIPSecPolicy :: IPSecPolicy -> CInt
packIPSecPolicy t = case t of
  IPSecPolicyDiscard -> #const IPSEC_POLICY_DISCARD
  IPSecPolicyNone -> #const IPSEC_POLICY_NONE
  IPSecPolicyIPSec -> #const IPSEC_POLICY_IPSEC
  IPSecPolicyEntrust -> #const IPSEC_POLICY_ENTRUST
  IPSecPolicyBypass -> #const IPSEC_POLICY_BYPASS
  
unpackIPSecPolicy :: CInt -> IPSecPolicy
unpackIPSecPolicy t = case t of
  (#const IPSEC_POLICY_DISCARD) -> IPSecPolicyDiscard
  (#const IPSEC_POLICY_NONE) -> IPSecPolicyNone
  (#const IPSEC_POLICY_IPSEC) -> IPSecPolicyIPSec
  (#const IPSEC_POLICY_ENTRUST) -> IPSecPolicyEntrust
  (#const IPSEC_POLICY_BYPASS) -> IPSecPolicyBypass

data IPSecLevel = IPSecLevelDefault
                | IPSecLevelUse
                | IPSecLevelRequire
                | IPSecLevelUnique
                deriving (Eq)

instance Show IPSecLevel where
  show IPSecLevelDefault = "default"
  show IPSecLevelUse = "use"
  show IPSecLevelRequire = "require"
  show IPSecLevelUnique = "unique"

instance Read IPSecLevel where
  readsPrec _ = 
    tryParse
    [ ("default", IPSecLevelDefault)
    , ("use", IPSecLevelUse)
    , ("require", IPSecLevelRequire)
    , ("unique", IPSecLevelUnique)
    ]

packIPSecLevel :: IPSecLevel -> CInt
packIPSecLevel t = case t of
  IPSecLevelDefault -> #const IPSEC_LEVEL_DEFAULT
  IPSecLevelUse -> #const IPSEC_LEVEL_USE
  IPSecLevelRequire -> #const IPSEC_LEVEL_REQUIRE
  IPSecLevelUnique -> #const IPSEC_LEVEL_UNIQUE
  
unpackIPSecLevel :: CInt -> IPSecLevel
unpackIPSecLevel t = case t of
  (#const IPSEC_LEVEL_DEFAULT) -> IPSecLevelDefault
  (#const IPSEC_LEVEL_USE) -> IPSecLevelUse
  (#const IPSEC_LEVEL_REQUIRE) -> IPSecLevelRequire
  (#const IPSEC_LEVEL_UNIQUE) -> IPSecLevelUnique

data NATTType = NATTType { natttypeType :: Int } deriving (Show, Eq)

instance Storable NATTType where
   alignment _ = #{alignment struct sadb_x_nat_t_type}
   sizeOf _ = #{size struct sadb_x_nat_t_type}  

instance Binary NATTType where
  put (NATTType typ) = do
    putWord8 $ fromIntegral typ
    putWord8 0
    putWord8 0
    putWord8 0
  get = do
    typ <- getWord8
    _ <- getWord8
    _ <- getWord8
    _ <- getWord8
    return $ NATTType { natttypeType = fromIntegral typ
                    }

data NATTPort = NATTPort { nattportPort :: Int } deriving (Show, Eq)

instance Storable NATTPort where
   alignment _ = #{alignment struct sadb_x_nat_t_port}
   sizeOf _ = #{size struct sadb_x_nat_t_port}  

instance Binary NATTPort where
  put (NATTPort port) = do
    putWord16be $ fromIntegral port
    putWord16le 0
  get = do
    port <- getWord16be    
    _ <- getWord16le
    return $ NATTPort { nattportPort = fromIntegral port
                      }

data SecCtx = SecCtx { ctxAlg :: Int
                     , ctxDoi :: Int
                     , ctxLen :: Int
                     } deriving (Show, Eq)

instance Storable SecCtx where
   alignment _ = #{alignment struct sadb_x_sec_ctx}
   sizeOf _ = #{size struct sadb_x_sec_ctx}  

instance Binary SecCtx where
  put (SecCtx alg doi len) = do
    putWord8 $ fromIntegral alg
    putWord8 $ fromIntegral doi
    putWord16le $ fromIntegral len
  get = do
    alg <- getWord8    
    doi <- getWord8
    len <- getWord16le
    return $ SecCtx { ctxAlg = fromIntegral alg
                    , ctxDoi = fromIntegral doi
                    , ctxLen = fromIntegral len
                    }

data KMAddress = KMAddress deriving (Show, Eq)

instance Storable KMAddress where
   alignment _ = #{alignment struct sadb_x_kmaddress}
   sizeOf _ = #{size struct sadb_x_kmaddress}  

instance Binary KMAddress where
  put _ = do
    putWord32le 0
  get = do
    _ <- getWord32le
    return KMAddress

data ExtType = ExtTypeReserved 
             | ExtTypeSA
             | ExtTypeLifetimeCurrent
             | ExtTypeLifetimeHard
             | ExtTypeLifetimeSoft
             | ExtTypeAddressSrc
             | ExtTypeAddressDst
             | ExtTypeAddressProxy
             | ExtTypeKeyAuth
             | ExtTypeKeyEncrypt
             | ExtTypeIdentitySrc
             | ExtTypeIdentityDst
             | ExtTypeSensitivity
             | ExtTypeProposal
             | ExtTypeSupportedAuth
             | ExtTypeSupportedEncrypt
             | ExtTypeSPIRange
             | ExtTypeKMPrivate
             | ExtTypePolicy
             | ExtTypeSA2
             | ExtTypeNATTType
             | ExtTypeNATTSPort
             | ExtTypeNATTDPort
             | ExtTypeNATTOA
             | ExtTypeSecCtx
             | ExtTypeKMAddress
             deriving (Show, Eq)
                      
packExtType :: ExtType -> CInt
packExtType t = case t of
  ExtTypeReserved -> #const SADB_EXT_RESERVED
  ExtTypeSA -> #const SADB_EXT_SA
  ExtTypeLifetimeCurrent -> #const SADB_EXT_LIFETIME_CURRENT
  ExtTypeLifetimeHard -> #const SADB_EXT_LIFETIME_HARD
  ExtTypeLifetimeSoft -> #const SADB_EXT_LIFETIME_SOFT
  ExtTypeAddressSrc -> #const SADB_EXT_ADDRESS_SRC
  ExtTypeAddressDst -> #const SADB_EXT_ADDRESS_DST
  ExtTypeAddressProxy -> #const SADB_EXT_ADDRESS_PROXY
  ExtTypeKeyAuth -> #const SADB_EXT_KEY_AUTH
  ExtTypeKeyEncrypt -> #const SADB_EXT_KEY_ENCRYPT
  ExtTypeIdentitySrc -> #const SADB_EXT_IDENTITY_SRC
  ExtTypeIdentityDst -> #const SADB_EXT_IDENTITY_DST
  ExtTypeSensitivity -> #const SADB_EXT_SENSITIVITY
  ExtTypeProposal -> #const SADB_EXT_PROPOSAL
  ExtTypeSupportedAuth -> #const SADB_EXT_SUPPORTED_AUTH
  ExtTypeSupportedEncrypt -> #const SADB_EXT_SUPPORTED_ENCRYPT
  ExtTypeSPIRange -> #const SADB_EXT_SPIRANGE
  ExtTypeKMPrivate -> #const SADB_X_EXT_KMPRIVATE
  ExtTypePolicy -> #const SADB_X_EXT_POLICY
  ExtTypeSA2 -> #const SADB_X_EXT_SA2
  ExtTypeNATTType -> #const SADB_X_EXT_NAT_T_TYPE
  ExtTypeNATTSPort -> #const SADB_X_EXT_NAT_T_SPORT
  ExtTypeNATTDPort -> #const SADB_X_EXT_NAT_T_DPORT
  ExtTypeNATTOA -> #const SADB_X_EXT_NAT_T_OA
  ExtTypeSecCtx -> #const SADB_X_EXT_SEC_CTX
  ExtTypeKMAddress -> #const SADB_X_EXT_KMADDRESS

unpackExtType :: CInt -> ExtType
unpackExtType t = case t of
  (#const SADB_EXT_RESERVED) -> ExtTypeReserved 
  (#const SADB_EXT_SA) -> ExtTypeSA
  (#const SADB_EXT_LIFETIME_CURRENT) -> ExtTypeLifetimeCurrent 
  (#const SADB_EXT_LIFETIME_HARD) -> ExtTypeLifetimeHard
  (#const SADB_EXT_LIFETIME_SOFT) -> ExtTypeLifetimeSoft
  (#const SADB_EXT_ADDRESS_SRC) -> ExtTypeAddressSrc
  (#const SADB_EXT_ADDRESS_DST) -> ExtTypeAddressDst
  (#const SADB_EXT_ADDRESS_PROXY) -> ExtTypeAddressProxy
  (#const SADB_EXT_KEY_AUTH) -> ExtTypeKeyAuth
  (#const SADB_EXT_KEY_ENCRYPT) -> ExtTypeKeyEncrypt
  (#const SADB_EXT_IDENTITY_SRC) -> ExtTypeIdentitySrc
  (#const SADB_EXT_IDENTITY_DST) -> ExtTypeIdentityDst
  (#const SADB_EXT_SENSITIVITY) -> ExtTypeSensitivity
  (#const SADB_EXT_PROPOSAL) -> ExtTypeProposal
  (#const SADB_EXT_SUPPORTED_AUTH) -> ExtTypeSupportedAuth
  (#const SADB_EXT_SUPPORTED_ENCRYPT) -> ExtTypeSupportedEncrypt
  (#const SADB_EXT_SPIRANGE) -> ExtTypeSPIRange
  (#const SADB_X_EXT_KMPRIVATE) -> ExtTypeKMPrivate
  (#const SADB_X_EXT_POLICY) -> ExtTypePolicy
  (#const SADB_X_EXT_SA2) -> ExtTypeSA2
  (#const SADB_X_EXT_NAT_T_TYPE) -> ExtTypeNATTType
  (#const SADB_X_EXT_NAT_T_SPORT) -> ExtTypeNATTSPort
  (#const SADB_X_EXT_NAT_T_DPORT) -> ExtTypeNATTDPort
  (#const SADB_X_EXT_NAT_T_OA) -> ExtTypeNATTOA
  (#const SADB_X_EXT_SEC_CTX) -> ExtTypeSecCtx
  (#const SADB_X_EXT_KMADDRESS) -> ExtTypeKMAddress
  _ -> error $ "unknown type: " ++ show t 

data AuthAlg = AuthAlgNone
             | AuthAlgMD5HMAC
             | AuthAlgSHA1HMAC
             | AuthAlgSHA2_256HMAC
             | AuthAlgSHA2_384HMAC
             | AuthAlgSHA2_512HMAC
             | AuthAlgRIPEMD160HMAC
             | AuthAlgAES_XCBC_MAC
             | AuthAlgNull
             deriving (Eq)

instance Show AuthAlg where
  show AuthAlgNone = "none"
  show AuthAlgMD5HMAC = "hmac-md5"
  show AuthAlgSHA1HMAC = "hmac-sha1"
  show AuthAlgSHA2_256HMAC = "hmac-sha2-256"
  show AuthAlgSHA2_384HMAC = "hmac-sha2-384"
  show AuthAlgSHA2_512HMAC = "hmac-sha2-512"
  show AuthAlgRIPEMD160HMAC = "hmac-ripemd160"
  show AuthAlgAES_XCBC_MAC = "aes-xcbc"
  show AuthAlgNull = "null"

packAuthAlg :: AuthAlg -> CInt
packAuthAlg t = case t of
  AuthAlgNone -> #const SADB_AALG_NONE
  AuthAlgMD5HMAC -> #const SADB_AALG_MD5HMAC
  AuthAlgSHA1HMAC -> #const SADB_AALG_SHA1HMAC
  AuthAlgSHA2_256HMAC -> #const SADB_X_AALG_SHA2_256HMAC
  AuthAlgSHA2_384HMAC -> #const SADB_X_AALG_SHA2_384HMAC
  AuthAlgSHA2_512HMAC -> #const SADB_X_AALG_SHA2_512HMAC
  AuthAlgRIPEMD160HMAC -> #const SADB_X_AALG_RIPEMD160HMAC
  AuthAlgAES_XCBC_MAC -> #const SADB_X_AALG_AES_XCBC_MAC
  AuthAlgNull -> #const SADB_X_AALG_NULL

unpackAuthAlg :: CInt -> AuthAlg
unpackAuthAlg t = case t of
  (#const SADB_AALG_NONE) -> AuthAlgNone
  (#const SADB_AALG_MD5HMAC) -> AuthAlgMD5HMAC
  (#const SADB_AALG_SHA1HMAC) -> AuthAlgSHA1HMAC
  (#const SADB_X_AALG_SHA2_256HMAC) -> AuthAlgSHA2_256HMAC
  (#const SADB_X_AALG_SHA2_384HMAC) -> AuthAlgSHA2_384HMAC
  (#const SADB_X_AALG_SHA2_512HMAC) -> AuthAlgSHA2_512HMAC
  (#const SADB_X_AALG_RIPEMD160HMAC) -> AuthAlgRIPEMD160HMAC
  (#const SADB_X_AALG_AES_XCBC_MAC) -> AuthAlgAES_XCBC_MAC
  (#const SADB_X_AALG_NULL) -> AuthAlgNull

data EncAlg = EncAlgNone
            | EncAlgDES_CBC
            | EncAlg3DES_CBC
            | EncAlgCAST_CBC
            | EncAlgBLOWFISH_CBC
            | EncAlgNull
            | EncAlgAES_CBC
            | EncAlgAES_CTR
            | EncAlgAES_CCM_ICV8
            | EncAlgAES_CCM_ICV12
            | EncAlgAES_CCM_ICV16
            | EncAlgAES_GCM_ICV8
            | EncAlgAES_GCM_ICV12
            | EncAlgAES_GCM_ICV16
            | EncAlgCamelliaCBC
            | EncAlgNullAES_GMAC
            | EncAlgSerpentCBC
            | EncAlgTwofishCBC
            deriving (Show, Eq)

packEncAlg :: EncAlg -> CInt
packEncAlg t = case t of
  EncAlgNone -> #const SADB_EALG_NONE
  EncAlgDES_CBC -> #const SADB_EALG_DESCBC
  EncAlg3DES_CBC -> #const SADB_EALG_3DESCBC
  EncAlgCAST_CBC -> #const SADB_X_EALG_CASTCBC
  EncAlgBLOWFISH_CBC -> #const SADB_X_EALG_BLOWFISHCBC
  EncAlgNull -> #const SADB_EALG_NULL
  EncAlgAES_CBC -> #const SADB_X_EALG_AESCBC
  EncAlgAES_CTR -> #const SADB_X_EALG_AESCTR
  EncAlgAES_CCM_ICV8 -> #const SADB_X_EALG_AES_CCM_ICV8
  EncAlgAES_CCM_ICV12 -> #const SADB_X_EALG_AES_CCM_ICV12
  EncAlgAES_CCM_ICV16 -> #const SADB_X_EALG_AES_CCM_ICV16
  EncAlgAES_GCM_ICV8 -> #const SADB_X_EALG_AES_GCM_ICV8
  EncAlgAES_GCM_ICV12 -> #const SADB_X_EALG_AES_GCM_ICV12
  EncAlgAES_GCM_ICV16 -> #const SADB_X_EALG_AES_GCM_ICV16
  EncAlgCamelliaCBC -> #const SADB_X_EALG_CAMELLIACBC
  EncAlgNullAES_GMAC -> #const SADB_X_EALG_NULL_AES_GMAC
  EncAlgSerpentCBC -> #const SADB_X_EALG_SERPENTCBC
  EncAlgTwofishCBC -> #const SADB_X_EALG_TWOFISHCBC

unpackEncAlg :: CInt -> EncAlg
unpackEncAlg t = case t of
  (#const SADB_EALG_NONE) -> EncAlgNone
  (#const SADB_EALG_DESCBC) -> EncAlgDES_CBC
  (#const SADB_EALG_3DESCBC) -> EncAlg3DES_CBC
  (#const SADB_X_EALG_CASTCBC) -> EncAlgCAST_CBC
  (#const SADB_X_EALG_BLOWFISHCBC) -> EncAlgBLOWFISH_CBC
  (#const SADB_EALG_NULL) -> EncAlgNull
  (#const SADB_X_EALG_AESCBC) -> EncAlgAES_CBC
  (#const SADB_X_EALG_AESCTR) -> EncAlgAES_CTR
  (#const SADB_X_EALG_AES_CCM_ICV8) -> EncAlgAES_CCM_ICV8
  (#const SADB_X_EALG_AES_CCM_ICV12) -> EncAlgAES_CCM_ICV12
  (#const SADB_X_EALG_AES_CCM_ICV16) -> EncAlgAES_CCM_ICV16
  (#const SADB_X_EALG_AES_GCM_ICV8) -> EncAlgAES_GCM_ICV8
  (#const SADB_X_EALG_AES_GCM_ICV12) -> EncAlgAES_GCM_ICV12
  (#const SADB_X_EALG_AES_GCM_ICV16) -> EncAlgAES_GCM_ICV16
  (#const SADB_X_EALG_CAMELLIACBC) -> EncAlgCamelliaCBC
  (#const SADB_X_EALG_NULL_AES_GMAC) -> EncAlgNullAES_GMAC
  (#const SADB_X_EALG_SERPENTCBC) -> EncAlgSerpentCBC
  (#const SADB_X_EALG_TWOFISHCBC) -> EncAlgTwofishCBC

{-
/* Encryption algorithms */
#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC             6
#define SADB_X_EALG_BLOWFISHCBC         7
#define SADB_EALG_NULL                  11
#define SADB_X_EALG_AESCBC              12
#define SADB_X_EALG_AESCTR              13
#define SADB_X_EALG_AES_CCM_ICV8        14
#define SADB_X_EALG_AES_CCM_ICV12       15
#define SADB_X_EALG_AES_CCM_ICV16       16
#define SADB_X_EALG_AES_GCM_ICV8        18
#define SADB_X_EALG_AES_GCM_ICV12       19
#define SADB_X_EALG_AES_GCM_ICV16       20
#define SADB_X_EALG_CAMELLIACBC         22
#define SADB_X_EALG_NULL_AES_GMAC       23
#define SADB_EALG_MAX                   253 /* last EALG */
/* private allocations should use 249-255 (RFC2407) */
#define SADB_X_EALG_SERPENTCBC  252     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
#define SADB_X_EALG_TWOFISHCBC  253     /* draft-ietf-ipsec-ciph-aes-cbc-00 */
-}

data CompAlg = CompAlgNone
             | CompAlgOUI
             | CompAlgDeflate
             | CompAlgLZS
             | CompAlgLZJH
             deriving (Show, Eq)

{-
/* Compression algorithms */
#define SADB_X_CALG_NONE                0
#define SADB_X_CALG_OUI                 1
#define SADB_X_CALG_DEFLATE             2
#define SADB_X_CALG_LZS                 3
#define SADB_X_CALG_LZJH                4
#define SADB_X_CALG_MAX                 4
-}

data IdentType = IdentTypeReserved
               | IdentTypePrefix
               | IdentTypeFQDN
               | IdentTypeUserFQDN
               deriving (Show, Eq)


  {-
/* Identity Extension values */
#define SADB_IDENTTYPE_RESERVED 0
#define SADB_IDENTTYPE_PREFIX   1
#define SADB_IDENTTYPE_FQDN     2
#define SADB_IDENTTYPE_USERFQDN 3
#define SADB_IDENTTYPE_MAX      3

-}