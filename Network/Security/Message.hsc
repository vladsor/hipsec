{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE ViewPatterns #-}

#include <linux/pfkeyv2.h>
#include <linux/ipsec.h>
#include <netinet/in.h>

module Network.Security.Message 
  ( Msg(..)
  , MsgHdr(..)
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
  , IPProto(..)
  , packIPProto
  , unpackIPProto
  , IPSecDir(..)
  , IPSecMode(..)
  , IPSecLevel
  , defaultMsg
  , Sizable(..)
  , Key(..)
  , EncAlg(..)
  , AuthAlg(..)
  , CompAlg(..)
  , SAState(..)
  , Supported(..)
  ) where

import qualified Data.ByteString.Lazy as LBS
import qualified Data.ByteString as BS
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import Foreign.C.Types ( CInt, CUInt, CChar, CSize )
import Control.Monad (liftM)
import Debug.Trace
import Data.Bits
import Control.Monad
import qualified Control.Monad.State as St
import Data.Maybe

import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.Time.Format
import Network.Socket (SockAddr(..), packFamily, unpackFamily, Family(..))
import Network.Socket.Internal (sizeOfSockAddrByFamily)
import Data.Monoid ((<>))

class Sizable a where
  sizeOf :: a -> Int

data MsgHdr = MsgHdr
  { msgHdrVersion :: Int
  , msgHdrType :: MsgType
  , msgHdrErrno :: Int
  , msgHdrSatype :: SAType
  , msgHdrLength :: Int
  , msgHdrSeq :: Int
  , msgHdrPid :: Int
  } deriving (Show, Eq)

data Msg = Msg 
  { msgVersion :: Int
  , msgType :: MsgType
  , msgErrno :: Int
  , msgSatype :: SAType
  , msgLength :: Int
  , msgSeq :: Int
  , msgPid :: Int
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

data IPProto = IPProtoAny
             | IPProtoESP
             | IPProtoAH
             | IPProtoIPComp
             | IPProtoIPIP
             | IPProtoIPv4
             | IPProtoICMPv6
             | IPProtoICMP
             | IPProtoUnknown Int
             deriving (Eq)

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

instance Sizable Msg where
   sizeOf _ = #{size struct sadb_msg}

instance Binary MsgHdr where
   put msg@(MsgHdr {..}) = do
     putWord8 $ fromIntegral msgHdrVersion
     putWord8 $ fromIntegral $ packMsgType msgHdrType
     putWord8 $ fromIntegral msgHdrErrno
     putWord8 $ fromIntegral $ packSAType msgHdrSatype
     putWord16le $ fromIntegral $ msgHdrLength
     putWord16le 0
     putWord32le $ fromIntegral msgHdrSeq
     putWord32le $ fromIntegral msgHdrPid
   get = do
     msgHdrVersion <- liftM fromIntegral getWord8
     msgHdrType <- liftM (unpackMsgType . fromIntegral) getWord8
     msgHdrErrno <- liftM fromIntegral getWord8
     msgHdrSatype <- liftM (unpackSAType . fromIntegral) getWord8
     msgHdrLength <- liftM fromIntegral getWord16le
     _ <- liftM fromIntegral getWord16le
     msgHdrSeq <- liftM fromIntegral getWord32le
     msgHdrPid <- liftM fromIntegral getWord32le
     return $ MsgHdr {..}

instance Binary Msg where
   put msg@(Msg{..}) = do
     putWord8 $ fromIntegral msgVersion
     putWord8 $ fromIntegral $ packMsgType msgType
     putWord8 $ fromIntegral msgErrno
     putWord8 $ fromIntegral $ packSAType msgSatype
     putWord16le $ fromIntegral $ msgLength' msg
     putWord16le 0
     putWord32le $ fromIntegral msgSeq
     putWord32le $ fromIntegral msgPid
     let putM a f = maybe (return ()) (put . f) a
     putM msgPolicy ExtensionPolicy
     putM msgSA ExtensionSA
     putM msgLifetimeCurrent ExtensionLifetimeCurrent
     putM msgLifetimeHard ExtensionLifetimeHard
     putM msgLifetimeSoft ExtensionLifetimeSoft
     putM msgAddressSrc ExtensionAddressSrc
     putM msgAddressDst ExtensionAddressDst
     putM msgAddressProxy ExtensionAddressProxy
     putM msgKeyAuth ExtensionKeyAuth
     putM msgKeyEncrypt ExtensionKeyEncrypt
     putM msgIdentitySrc ExtensionIdentitySrc
     putM msgIdentityDst ExtensionIdentityDst
     putM msgSensitivity ExtensionSensitivity
     putM msgProposal ExtensionProposal
     putM msgSupportedAuth ExtensionSupportedAuth
     putM msgSupportedEncrypt ExtensionSupportedEncrypt
     putM msgSPIRange ExtensionSPIRange
     putM msgKMPrivate ExtensionKMPrivate
     putM msgSA2 ExtensionSA2
     putM msgNATTType ExtensionNATTType
     putM msgNATTSPort ExtensionNATTSPort
     putM msgNATTDPort ExtensionNATTDPort
     putM msgNATTOA ExtensionNATTOA
     putM msgSecCtx ExtensionSecCtx
     putM msgKMAddress ExtensionKMAddress

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
     if bodylen > 0 then do
         repeateL (fromIntegral bodylen, hdr) updateMsgCnt'
       else
       return hdr

updateMsgCnt' :: (Int, Msg) -> Get (Int, Msg)
updateMsgCnt' (0, msg) = return (0, msg)
updateMsgCnt' (left, Msg{..}) = do
  off <- liftM fromIntegral bytesRead
  ext <- get
  off' <- liftM fromIntegral bytesRead
  return . (left - (off' - off),) $ case ext of
    ExtensionSA (Just -> msgSA) -> Msg{..}
    ExtensionLifetimeCurrent (Just -> msgLifetimeCurrent) -> Msg{..}
    ExtensionLifetimeHard (Just -> msgLifetimeHard) -> Msg{..}
    ExtensionLifetimeSoft (Just -> msgLifetimeSoft) -> Msg{..}
    ExtensionAddressSrc (Just -> msgAddressSrc) -> Msg{..}
    ExtensionAddressDst (Just -> msgAddressDst) -> Msg{..}
    ExtensionAddressProxy (Just -> msgAddressProxy) -> Msg{..}
    ExtensionKeyAuth (Just -> msgKeyAuth) -> Msg{..}
    ExtensionKeyEncrypt (Just -> msgKeyEncrypt) -> Msg{..}
    ExtensionIdentitySrc (Just -> msgIdentitySrc) -> Msg{..}
    ExtensionIdentityDst (Just -> msgIdentityDst) -> Msg{..}
    ExtensionSensitivity (Just -> msgSensitivity) -> Msg{..}
    ExtensionProposal (Just -> msgProposal) -> Msg{..}
    ExtensionSupportedAuth (Just -> msgSupportedAuth) -> Msg{..}
    ExtensionSupportedEncrypt (Just -> msgSupportedEncrypt) -> Msg{..}
    ExtensionSPIRange (Just -> msgSPIRange) -> Msg{..}
    ExtensionKMPrivate (Just -> msgKMPrivate) -> Msg{..}
    ExtensionPolicy (Just -> msgPolicy) -> Msg{..}
    ExtensionSA2 (Just -> msgSA2) -> Msg{..}
    ExtensionNATTType (Just -> msgNATTType) -> Msg{..}
    ExtensionNATTSPort (Just -> msgNATTSPort) -> Msg{..}
    ExtensionNATTDPort (Just -> msgNATTDPort) -> Msg{..}
    ExtensionNATTOA (Just -> msgNATTOA) -> Msg{..}
    ExtensionSecCtx (Just -> msgSecCtx) -> Msg{..}
    ExtensionKMAddress (Just -> msgKMAddress) -> Msg{..}
    _ -> Msg{..}


msgLength' :: Msg -> Int
msgLength' Msg{..} = (`shiftR` 3) $ #{size struct sadb_msg}
    + sum 
    [ mlen msgSA
    , mlen msgLifetimeCurrent
    , mlen msgLifetimeHard
    , mlen msgLifetimeSoft
    , mlen msgAddressSrc
    , mlen msgAddressDst
    , mlen msgAddressProxy
    , mlen msgKeyAuth
    , mlen msgKeyEncrypt
    , mlen msgIdentitySrc
    , mlen msgIdentityDst
    , mlen msgSensitivity
    , mlen msgProposal
    , mlen msgSupportedAuth
    , mlen msgSupportedEncrypt
    , mlen msgSPIRange
    , mlen msgKMPrivate
    , mlen msgPolicy
    , mlen msgSA2
    , mlen msgNATTType
    , mlen msgNATTSPort
    , mlen msgNATTDPort
    , mlen msgNATTOA
    , mlen msgSecCtx
    , mlen msgKMAddress
    ]
    where 
      mlen :: Sizable a => Maybe a -> Int
      mlen = maybe 0 sizeOf

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
            deriving (Eq)

instance Show SAType where
  show SATypeUnspec = "unspec"
  show SATypeUnspec1 = "unknown"
  show SATypeAH = "ah"
  show SATypeESP = "esp"
  show SATypeRSVP = "rsvp"
  show SATypeOSPFv2 = "ospfv2"
  show SATypeRIPv2 = "ripv2"
  show SATypeMIP = "mip"
  show SATypeIPComp = "ipcomp"

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

instance Read SAType where
  readsPrec _ =
    tryParse
      [ ("unspec", SATypeUnspec)
      , ("unknown", SATypeUnspec1)
      , ("ah", SATypeAH)
      , ("esp", SATypeESP)
      , ("rsvp", SATypeRSVP)
      , ("ospfv2", SATypeOSPFv2)
      , ("ripv2", SATypeRIPv2)
      , ("mip", SATypeMIP)
      , ("ipcomp", SATypeIPComp)
      ]

data ExtHdr = ExtHdr { exthdrLen :: Int
                     , exthdrType :: Int
                     } deriving (Show, Eq)

instance Sizable ExtHdr where
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

data Extension
  = ExtensionUnknown BS.ByteString
  | ExtensionSA SA
  | ExtensionLifetimeCurrent Lifetime
  | ExtensionLifetimeHard Lifetime
  | ExtensionLifetimeSoft Lifetime
  | ExtensionAddressSrc Address
  | ExtensionAddressDst Address
  | ExtensionAddressProxy Address
  | ExtensionKeyAuth Key
  | ExtensionKeyEncrypt Key
  | ExtensionIdentitySrc Identity
  | ExtensionIdentityDst Identity
  | ExtensionSensitivity Sensitivity
  | ExtensionProposal Proposal
  | ExtensionSupportedAuth Supported
  | ExtensionSupportedEncrypt Supported
  | ExtensionSPIRange SPIRange
  | ExtensionKMPrivate KMPrivate
  | ExtensionPolicy Policy
  | ExtensionSA2 SA2
  | ExtensionNATTType NATTType
  | ExtensionNATTSPort NATTPort
  | ExtensionNATTDPort NATTPort
  | ExtensionNATTOA Address
  | ExtensionSecCtx SecCtx
  | ExtensionKMAddress KMAddress
  deriving (Eq, Show)

putAddr (Address proto prefixlen addr) = do
    putWord8 $ fromIntegral proto
    putWord8 $ fromIntegral prefixlen
    putWord16le 0
    put addr
putKey (Key bits blob) = do
    putWord16le $ fromIntegral bits
    putWord16le 0
    putByteString blob
putPolicy (Policy typ dir id prio reqs) = do
    putWord16le $ fromIntegral $ packIPSecPolicy typ
    putWord8 $ fromIntegral $ packIPSecDir dir
    putWord8 0
    putWord32le $ fromIntegral id
    putWord32le $ fromIntegral prio
    mapM_ put reqs
putSupported (Supported algs)= do
    putWord32le 0
    mapM_ put algs

instance Binary Extension where
  put (ExtensionUnknown blob) = do
    putWord16le $ fromIntegral $ (4 + BS.length blob) `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_RESERVED
    putByteString blob
  put (ExtensionSA sa) = do
    putWord16le $ fromIntegral $ sizeOf sa `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_SA
    put sa
  put (ExtensionLifetimeCurrent ltm) = do
    putWord16le $ fromIntegral $ sizeOf ltm `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_LIFETIME_CURRENT
    put ltm
  put (ExtensionLifetimeHard ltm) = do
    putWord16le $ fromIntegral $ sizeOf ltm `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_LIFETIME_HARD
    put ltm
  put (ExtensionLifetimeSoft ltm) = do
    putWord16le $ fromIntegral $ sizeOf ltm `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_LIFETIME_SOFT
    put ltm
  put (ExtensionAddressSrc addr) = do
    putWord16le $ fromIntegral $ sizeOf addr `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_ADDRESS_SRC
    putAddr addr
  put (ExtensionAddressDst addr) = do
    putWord16le $ fromIntegral $ sizeOf addr `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_ADDRESS_DST
    putAddr addr
  put (ExtensionAddressProxy addr) = do
    putWord16le $ fromIntegral $ sizeOf addr `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_ADDRESS_PROXY
    putAddr addr
  put (ExtensionKeyAuth key) = do
    putWord16le $ fromIntegral $ sizeOf key `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_KEY_AUTH
    putKey key
  put (ExtensionKeyEncrypt key) = do
    putWord16le $ fromIntegral $ sizeOf key `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_KEY_ENCRYPT
    putKey key
  put (ExtensionIdentitySrc iden) = do
    putWord16le $ fromIntegral $ sizeOf iden `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_IDENTITY_SRC
    put iden
  put (ExtensionIdentityDst iden) = do
    putWord16le $ fromIntegral $ sizeOf iden `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_IDENTITY_DST
    put iden
  put (ExtensionSensitivity sens) = do
    putWord16le $ fromIntegral $ sizeOf sens `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_SENSITIVITY
    put sens
  put (ExtensionProposal prop) = do
    putWord16le $ fromIntegral $ sizeOf prop `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_PROPOSAL
    put prop
  put (ExtensionSupportedAuth supp) = do
    putWord16le $ fromIntegral $ sizeOf supp `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_SUPPORTED_AUTH
    putSupported supp
  put (ExtensionSupportedEncrypt supp) = do
    putWord16le $ fromIntegral $ sizeOf supp `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_SUPPORTED_ENCRYPT
    putSupported supp
  put (ExtensionSPIRange range) = do
    putWord16le $ fromIntegral $ sizeOf range `shiftR` 3
    putWord16le $ fromIntegral #const SADB_EXT_SPIRANGE
    put range
  put (ExtensionKMPrivate kmp) = do
    putWord16le $ fromIntegral $ sizeOf kmp `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_KMPRIVATE
    put kmp
  put (ExtensionPolicy pol) = do
    putWord16le $ fromIntegral $ sizeOf pol `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_POLICY
    putPolicy pol
  put (ExtensionSA2 sa2) = do
    putWord16le $ fromIntegral $ sizeOf sa2 `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_SA2
    put sa2
  put (ExtensionNATTType typ) = do
    putWord16le $ fromIntegral $ sizeOf typ `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_NAT_T_TYPE
    put typ
  put (ExtensionNATTSPort port) = do
    putWord16le $ fromIntegral $ sizeOf port `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_NAT_T_SPORT
    put port
  put (ExtensionNATTDPort port) = do
    putWord16le $ fromIntegral $ sizeOf port `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_NAT_T_DPORT
    put port
  put (ExtensionNATTOA addr) = do
    putWord16le $ fromIntegral $ sizeOf addr `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_NAT_T_OA
    putAddr addr
  put (ExtensionSecCtx ctx) = do
    putWord16le $ fromIntegral $ sizeOf ctx `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_SEC_CTX
    put ctx
  put (ExtensionKMAddress kmaddr) = do
    putWord16le $ fromIntegral $ sizeOf kmaddr `shiftR` 3
    putWord16le $ fromIntegral #const SADB_X_EXT_KMADDRESS
    put kmaddr

  get = do
    len <- liftM ((*8) . fromIntegral) getWord16le :: Get Int
    typ <- liftM fromIntegral getWord16le
    let
      getPolicy = do
        let left = len - fromIntegral (#{size struct sadb_x_policy})
        policyType <- liftM (unpackIPSecPolicy . fromIntegral) getWord16le
        policyDir <- liftM (unpackIPSecDir . fromIntegral) getWord8
        _ <- getWord8
        policyId <- liftM fromIntegral getWord32le
        policyPriority <- liftM fromIntegral getWord32le
        policyIPSecRequests <- readArray left get
        return Policy{..}

      getAddress = do
        addressProto <- liftM fromIntegral getWord8
        addressPrefixLen <- liftM fromIntegral getWord8
        _ <- getWord16le
        addressAddr <- get
{-        
        family <- getWord16le >>= return . unpackFamily . fromIntegral
        let left = len - #{size struct sadb_address}
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
              return $ SockAddrInet6 (fromIntegral port) flowinfo (ha0, ha1, ha2, ha3) scopeid
            AF_INET -> do
              port <- getWord16le
              inet <- getWord32le
              _ <- getByteString $ left - 8
              return $ SockAddrInet (fromIntegral port) inet
            _ -> error "unsupported family"
-}
        return Address{..}

      getKey = do
        bits <- getWord16le
        _ <- getWord16le
        let left =  len - #{size struct sadb_key}
        if (fromIntegral bits > left * 8) then error ("invalid len for key" ++ show bits) else do
          dat <- getByteString $ fromIntegral $ bits `shiftR` 3
          let padlen = left - (fromIntegral bits) `shiftR` 3
          _  <- getByteString $ fromIntegral padlen
          return $ Key { keyBits = fromIntegral bits, keyData = dat}
      getSupported = do
        _ <- getWord32le
        let left = len - fromIntegral (#{size struct sadb_supported})
        supportedAlgs <- readArray left get
        return Supported {..}
    case typ of
      (#const SADB_EXT_RESERVED) -> liftM ExtensionUnknown (getByteString (len - 4))
      (#const SADB_EXT_SA) -> liftM ExtensionSA get
      (#const SADB_EXT_LIFETIME_CURRENT) -> liftM ExtensionLifetimeCurrent get
      (#const SADB_EXT_LIFETIME_HARD) -> liftM ExtensionLifetimeHard get
      (#const SADB_EXT_LIFETIME_SOFT) -> liftM ExtensionLifetimeSoft get
      (#const SADB_EXT_ADDRESS_SRC) -> liftM ExtensionAddressSrc getAddress
      (#const SADB_EXT_ADDRESS_DST) -> liftM ExtensionAddressDst getAddress
      (#const SADB_EXT_ADDRESS_PROXY) -> liftM ExtensionAddressProxy getAddress
      (#const SADB_EXT_KEY_AUTH) -> liftM ExtensionKeyAuth getKey
      (#const SADB_EXT_KEY_ENCRYPT) -> liftM ExtensionKeyEncrypt getKey
      (#const SADB_EXT_IDENTITY_SRC) -> liftM ExtensionIdentitySrc get
      (#const SADB_EXT_IDENTITY_DST) -> liftM ExtensionIdentityDst get
      (#const SADB_EXT_SENSITIVITY) -> liftM ExtensionSensitivity get
      (#const SADB_EXT_PROPOSAL) -> liftM ExtensionProposal get
      (#const SADB_EXT_SUPPORTED_AUTH) -> liftM ExtensionSupportedAuth getSupported
      (#const SADB_EXT_SUPPORTED_ENCRYPT) -> liftM ExtensionSupportedEncrypt getSupported
      (#const SADB_EXT_SPIRANGE) -> liftM ExtensionSPIRange get
      (#const SADB_X_EXT_KMPRIVATE) -> liftM ExtensionKMPrivate get
      (#const SADB_X_EXT_POLICY) -> liftM ExtensionPolicy getPolicy

      (#const SADB_X_EXT_SA2) -> liftM ExtensionSA2 get
      (#const SADB_X_EXT_NAT_T_TYPE) -> liftM ExtensionNATTType get
      (#const SADB_X_EXT_NAT_T_SPORT) -> liftM ExtensionNATTSPort get
      (#const SADB_X_EXT_NAT_T_DPORT) -> liftM ExtensionNATTDPort get
      (#const SADB_X_EXT_NAT_T_OA) -> liftM ExtensionNATTOA getAddress
      (#const SADB_X_EXT_SEC_CTX) -> liftM ExtensionSecCtx get
      (#const SADB_X_EXT_KMADDRESS) -> liftM ExtensionKMAddress get

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

instance Sizable SA where
   sizeOf _ = #{size struct sadb_sa}

instance Binary SA where
  put (SA spi replay state auth encrypt flags) = do
    putWord32be $ fromIntegral spi
    putWord8 $ fromIntegral replay
    putWord8 $ fromIntegral $ packSAState state
    putWord8 $ fromIntegral $ packAuthAlg auth
    putWord8 $ fromIntegral $ packEncAlg encrypt
    putWord32le $ fromIntegral flags
  get = do
    spi <- getWord32be
    replay <- getWord8
    state <- getWord8
    auth <- getWord8
    encrypt <- getWord8
    flags <- getWord32le
    return $ SA { saSPI = fromIntegral spi
                , saReplay = fromIntegral replay
                , saState = unpackSAState $ fromIntegral state
                , saAuth = unpackAuthAlg $ fromIntegral auth
                , saEncrypt = unpackEncAlg $ fromIntegral encrypt
                , saFlags = fromIntegral flags
                }

data Lifetime = Lifetime { ltAllocations :: Int
                         , ltBytes :: Int
                         , ltAddTime :: UTCTime
                         , ltUseTime :: UTCTime
                         } deriving (Show, Eq)
                
instance Sizable Lifetime where
   sizeOf _ = #{size struct sadb_lifetime}  

instance Binary Lifetime where
  put (Lifetime allocations bytes addtime usetime) = do
    putWord32le $ fromIntegral allocations
    putWord64le $ fromIntegral bytes
    putWord64le $ fromIntegral $ fromEnum $ utcTimeToPOSIXSeconds addtime
    putWord64le $ fromIntegral $ fromEnum $ utcTimeToPOSIXSeconds usetime
  get = do
    allocations <- getWord32le
    bytes <- getWord64le
    addtime <- getWord64le
    usetime <- getWord64le
    return $ Lifetime { ltAllocations = fromIntegral allocations
                                     , ltBytes = fromIntegral bytes
                                     , ltAddTime = posixSecondsToUTCTime $ fromIntegral addtime
                                     , ltUseTime = posixSecondsToUTCTime $ fromIntegral usetime
                                     }

data Address = Address { addressProto :: Int
                       , addressPrefixLen :: Int
                       , addressAddr :: SockAddr
                       } deriving (Show, Eq)

instance Sizable Address where
   sizeOf (Address _ _ addr) = #{size struct sadb_address} + sizeOf addr

instance Sizable SockAddr where
   sizeOf addr =
     case addr of
          SockAddrInet6 _ _ _ _ -> #{size struct sockaddr_in6}
          SockAddrInet _ _ -> #{size struct sockaddr_in}

instance Binary SockAddr where
  put addr = do
    case addr of
      SockAddrInet6 port flowinfo (ha0, ha1, ha2, ha3) scopeid -> do
        putWord16le $ fromIntegral $ packFamily AF_INET6
        putWord16le $ fromIntegral port
        putWord32be flowinfo
        putWord32be ha0
        putWord32be ha1
        putWord32be ha2
        putWord32be ha3
        putWord32le scopeid
        putWord16le 0
      SockAddrInet port inet -> do
        putWord16le $ fromIntegral $ packFamily AF_INET
        putWord16le $ fromIntegral port
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
        return $ SockAddrInet6 (fromIntegral port) flowinfo (ha0, ha1, ha2, ha3) scopeid
      AF_INET -> do
        port <- getWord16le
        inet <- getWord32le
        _ <- getByteString 8
        return $ SockAddrInet (fromIntegral port) inet
      _ -> error $ "unsupported family:" ++ show family
    return addr

data Key = Key { keyBits :: Int
               , keyData :: BS.ByteString
               } deriving (Show, Eq)

instance Sizable Key where
   sizeOf _ = #{size struct sadb_key}  

data Identity = Identity { identType :: Int
                         , identId :: Int
                         } deriving (Show, Eq)

instance Sizable Identity where
   sizeOf _ = #{size struct sadb_ident}  

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

instance Sizable Sensitivity where
   sizeOf _ = #{size struct sadb_sens}  

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

instance Sizable Proposal where
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

instance Sizable Supported where
   sizeOf _ = #{size struct sadb_supported}

{-
instance Binary Supported where
  put (Supported algs) = do
    putWord32le 0
  get = do
    _ <- getWord32le
    return $ Supported { supportedAlgs = [] }
-}

data Alg = Alg { algId :: Int
               , algIvLen :: Int
               , algMinBits :: Int
               , algMaxBits :: Int
               } deriving (Show, Eq)

instance Binary Alg where
  put (Alg{..}) = do
    putWord8 $ fromIntegral algId
    putWord8 $ fromIntegral algIvLen
    putWord16le $ fromIntegral algMinBits
    putWord16le $ fromIntegral algMaxBits
    putWord16le 0
  get = do
    algId <- liftM fromIntegral getWord8
    algIvLen <- liftM fromIntegral getWord8
    algMinBits <- liftM fromIntegral getWord16le
    algMaxBits <- liftM fromIntegral getWord16le
    _ <- getWord16le
    return Alg{..}

data SPIRange = SPIRange { spirangeMin :: Int
                         , spirangeMax :: Int
                         } deriving (Show, Eq)

instance Sizable SPIRange where
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

instance Sizable KMPrivate where
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

instance Sizable SA2 where
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

instance Sizable Policy where
   sizeOf p = #{size struct sadb_x_policy} + sum (fmap sizeOf (policyIPSecRequests p))

readArray :: Int -> Get a -> Get [a]
readArray left f = do
  if (left == 0) then return [] 
    else do
    off <- bytesRead >>= return . fromIntegral
    a <- f
    off' <- bytesRead >>= return . fromIntegral
    as <- (readArray (left + off - off') f)
    return $ a : as

data IPSecRequest = IPSecRequest { ipsecreqProto :: IPProto
                                 , ipsecreqMode :: IPSecMode
                                 , ipsecreqLevel :: IPSecLevel
                                 , ipsecreqReqId :: Int
                                 , ipsecreqAddrs :: Maybe (SockAddr, SockAddr)
                                 } deriving (Show, Eq)


instance Sizable IPSecRequest where
  sizeOf (IPSecRequest proto mode level reqid Nothing) =  #{size struct sadb_x_ipsecrequest}
  sizeOf (IPSecRequest proto mode level reqid (Just (saddr, daddr))) = #{size struct sadb_x_ipsecrequest} + sizeOf saddr + sizeOf daddr

instance Binary IPSecRequest where
  put (IPSecRequest proto mode level reqid Nothing) = do
    putWord16le $ #{size struct sadb_x_ipsecrequest}
    putWord16le $ fromIntegral $ packIPProto proto
    putWord8 $ fromIntegral $ packIPSecMode mode 
    putWord8 $ fromIntegral $ packIPSecLevel level
    putWord16le 0
    putWord32le $ fromIntegral reqid
    putWord32le 0
  put (IPSecRequest proto mode level reqid (Just (saddr, daddr))) = do
    putWord16le $ fromIntegral $ #{size struct sadb_x_ipsecrequest} + sizeOf saddr + sizeOf daddr
    putWord16le $ fromIntegral $ packIPProto proto
    putWord8 $ fromIntegral $ packIPSecMode mode
    putWord8 $ fromIntegral $ packIPSecLevel level
    putWord16le 0
    putWord32le $ fromIntegral reqid
    putWord32le 0
    put saddr
    put daddr
  get = do
    len <- getWord16le -- >>= return . fromIntegral
    ipsecreqProto <- liftM (unpackIPProto . fromIntegral) getWord16le
    ipsecreqMode <- getWord8 >>= return . unpackIPSecMode . fromIntegral
    ipsecreqLevel <- getWord8 >>= return . unpackIPSecLevel . fromIntegral
    _ <- getWord16le
    ipsecreqReqId <- liftM fromIntegral getWord32le
    _ <- getWord32le
    let left = len - #{size struct sadb_x_ipsecrequest}
    ipsecreqAddrs <- if left == 0 then return Nothing
             else do
               addr1 <- get
               addr2 <- get
               return $ Just (addr1, addr2)
    return IPSecRequest{..}

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

instance Sizable NATTType where
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

instance Sizable NATTPort where
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

instance Sizable SecCtx where
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

instance Sizable KMAddress where
   sizeOf _ = #{size struct sadb_x_kmaddress}  

instance Binary KMAddress where
  put _ = do
    putWord32le 0
  get = do
    _ <- getWord32le
    return KMAddress

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

instance Read AuthAlg where
  readsPrec _ =
    tryParse
      [ ("none", AuthAlgNone)
      , ("hmac-md5", AuthAlgMD5HMAC)
      , ("hmac-sha1", AuthAlgSHA1HMAC)
      , ("hmac-sha2-256", AuthAlgSHA2_256HMAC)
      , ("hmac-sha2-384", AuthAlgSHA2_384HMAC)
      , ("hmac-sha2-512", AuthAlgSHA2_512HMAC)
      , ("hmac-ripemd160", AuthAlgRIPEMD160HMAC)
      , ("aes-xcbc", AuthAlgAES_XCBC_MAC)
      , ("null", AuthAlgNull)
      ]

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
            deriving (Eq)

instance Show EncAlg where
  show EncAlgNone = "none"
  show EncAlgDES_CBC = "des-cbc"
  show EncAlg3DES_CBC = "3des-cbc"
  show EncAlgCAST_CBC = "cast-cbc"
  show EncAlgBLOWFISH_CBC = "blowfish-cbc"
  show EncAlgNull = "null"
  show EncAlgAES_CBC = "aes-cbc"
  show EncAlgAES_CTR = "aes-ctr"
  show EncAlgAES_CCM_ICV8 = "aes-ccm-icv8"
  show EncAlgAES_CCM_ICV12 = "aes-ccm-icv12"
  show EncAlgAES_CCM_ICV16 = "aes-ccm-icv16"
  show EncAlgAES_GCM_ICV8 = "aes-gcm-icv8"
  show EncAlgAES_GCM_ICV12 = "aes-gcm-icv12"
  show EncAlgAES_GCM_ICV16 = "aes-gcm-icv16"
  show EncAlgCamelliaCBC = "camellia-cbc"
  show EncAlgNullAES_GMAC = "null-aes-gmac"
  show EncAlgSerpentCBC = "serpent-cbc"
  show EncAlgTwofishCBC = "twofish-cbc"

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

instance Read EncAlg where
  readsPrec _ =
    tryParse
      [ ("none", EncAlgNone)
      , ("des-cbc", EncAlgDES_CBC)
      , ("3des-cbc", EncAlg3DES_CBC)
      , ("cast-cbc", EncAlgCAST_CBC)
      , ("blowfish-cbc", EncAlgBLOWFISH_CBC)
      , ("null", EncAlgNull)
      , ("aes-cbc", EncAlgAES_CBC)
      , ("aes-ctr", EncAlgAES_CTR)
      , ("aes-ccm-icv8", EncAlgAES_CCM_ICV8)
      , ("aes-ccm-icv12", EncAlgAES_CCM_ICV12)
      , ("aes-ccm-icv16", EncAlgAES_CCM_ICV16)
      , ("aes-gcm-icv8", EncAlgAES_GCM_ICV8)
      , ("aes-gcm-icv12", EncAlgAES_GCM_ICV12)
      , ("aes-gcm-icv16", EncAlgAES_GCM_ICV16)
      , ("camellia-cbc", EncAlgCamelliaCBC)
      , ("null-aes-gmac", EncAlgNullAES_GMAC)
      , ("serpent-cbc", EncAlgSerpentCBC)
      , ("twofish-cbc", EncAlgTwofishCBC)
    ]

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
