{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE TypeFamilies #-}

module Network.Security.PFSocket where

import Network.Security.Message (MsgHdr(..), Msg(..))
import qualified Network.Security.Message as Message

import Foreign.Ptr
import Foreign.Marshal.Alloc
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy.Char8 as LBS
import Data.Binary

import System.Posix.IO.Select
import System.Posix.IO.Select.FdSet
import System.Posix.IO.Select.Types
import Foreign.C.Types
import System.Posix.Types

import System.Socket
import System.Socket.Unsafe

import Foreign
import Foreign.C
import Data.Monoid

import Control.Concurrent.MVar

foreign import ccall "ioctl" c_ioctl :: CInt -> CInt -> Ptr () -> IO CInt
foreign import capi "sys/ioctl.h value FIONREAD" c_fionread :: CInt
foreign import capi "sys/socket.h value PF_KEY" c_pf_key :: CInt
foreign import capi "sys/socket.h value SO_RCVBUF" c_so_rcvbuf :: CInt
foreign import capi "sys/socket.h value SO_SNDBUF" c_so_sndbuf :: CInt
foreign import capi "sys/socket.h value MSG_PEEK" c_msg_peek :: CInt

data Pseudo_AF_KEY = Pseudo_AF_KEY
instance Storable Pseudo_AF_KEY where
  sizeOf _ = 0
  alignment _ = 0
  peek _ = return Pseudo_AF_KEY
  poke _ _ = return ()

instance Family Pseudo_AF_KEY where
  type SocketAddress Pseudo_AF_KEY = Pseudo_AF_KEY
  familyNumber _ = c_pf_key

data PfKeyV2

instance Protocol PfKeyV2 where
  protocolNumber = const 2

data RecvBuffer = RecvBuffer CInt

instance SetSocketOption RecvBuffer where
  setSocketOption s (RecvBuffer sz) = unsafeSetSocketOption s (1) c_so_rcvbuf sz

data SendBuffer = SendBuffer CInt
instance SetSocketOption SendBuffer where
  setSocketOption s (SendBuffer sz) = unsafeSetSocketOption s (1) c_so_sndbuf sz

type PfSocket = Socket Pseudo_AF_KEY Raw PfKeyV2

pfkey_open :: IO PfSocket
pfkey_open = do
  s <- socket :: IO PfSocket
  setSocketOption s $ RecvBuffer (1024 * 1024)
  setSocketOption s $ SendBuffer (128 * 1024)
  return s

pfkey_close :: PfSocket -> IO ()
pfkey_close = close

c_ioctl' :: Fd -> Ptr d -> IO ()
c_ioctl' (Fd fd) p =
    throwErrnoIfMinus1_ "ioctl" $
            c_ioctl fd c_fionread (castPtr p)

ioctlsocket' :: Fd -- ^ The socket
             -> IO CInt -- ^ The data
ioctlsocket' fd = alloca $ \p -> c_ioctl' fd p >> peek p

pfkey_recv :: PfSocket -> IO (Maybe Msg)
pfkey_recv s@(Socket mfd) = do
  let hdrlen = (Message.sizeOf (undefined::Msg)) :: Int
  withMVar mfd $ \fd -> do
    ret <- select'' [fd] [] [] (Time (CTimeval 10 0))
    putStrLn $ "select:" ++ show ret
    return ()
  buf <- receive s (fromIntegral hdrlen) (MessageFlags c_msg_peek)
  let hdr = decode (LBS.fromStrict buf)
  let msglen = (msgHdrLength hdr) `shift` 3
  buf <- if msglen > 0 then receive s (fromIntegral msglen) mempty else return mempty
  return $ if (BS.length buf /= msglen) then Nothing else Just $ decode $ LBS.fromStrict $ buf

pfkey_send :: PfSocket -> Msg -> IO ()
pfkey_send s msg = do
  send s (LBS.toStrict (encode msg)) mempty
  return ()
