{-# LANGUAGE CPP, ScopedTypeVariables #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE DeriveDataTypeable #-}


#include "HsNet.h"

-- NOTE: ##, we want this interpreted when compiling the .hs, not by hsc2hs.
##include "Typeable.h"

-- In order to process this file, you need to have CALLCONV defined.

module Network.Security.Internal.PFSocket
    (
    -- * Types
      Socket

    -- * Socket operations
    , socket

    -- ** Sending and receiving data
    -- $sendrecv
    , send
    , recv
    , recvLen
    , sendBuf
    , recvBuf

    , close

    -- * Socket options
    , SocketOption(..)
    , isSupportedSocketOption
    , getSocketOption
    , setSocketOption

    ) where

import Data.Bits
import Data.List (delete, foldl')
import Data.Maybe (fromMaybe, isJust)
import Data.Word (Word8, Word16, Word32)
import Foreign.Ptr (Ptr, castPtr, nullPtr)
import Foreign.Storable (Storable(..))
import Foreign.C.Error
import Foreign.C.String (CString, withCString, withCStringLen, peekCString, peekCStringLen)
import Foreign.C.Types (CUInt, CChar)
import Foreign.C.Types (CInt(..), CSize(..))
import Foreign.Marshal.Alloc ( alloca, allocaBytes )
import Foreign.Marshal.Array ( peekArray )
import Foreign.Marshal.Utils ( maybeWith, with )

import System.IO
import Control.Monad (liftM, when)
import Data.Ratio ((%))

import qualified Control.Exception as E
import Control.Concurrent.MVar
import Data.Typeable
import System.IO.Error

import GHC.Conc (threadWaitRead, threadWaitWrite)

import qualified GHC.IO.Device
import GHC.IO.Handle.FD
import GHC.IO.Exception
import GHC.IO

import qualified System.Posix.Internals

import Foreign.C.Error (throwErrno, throwErrnoIfMinus1Retry,
                        throwErrnoIfMinus1RetryMayBlock, throwErrnoIfMinus1_,
                        Errno(..), errnoToIOError)

-----------------------------------------------------------------------------
-- Socket types


data Socket
  = MkSocket
            CInt                 -- File Descriptor
  deriving Typeable

sockFd (MkSocket fd) = fd

socket :: IO Socket
socket = do
    fd <- throwSocketErrorIfMinus1Retry "socket" $
                c_socket (#const PF_KEY) (#const SOCK_RAW) 2
    setNonBlockIfNeeded fd
    let sock = MkSocket fd
    return sock

-- | Set the socket to nonblocking, if applicable to this platform.
setNonBlockIfNeeded :: CInt -> IO ()
setNonBlockIfNeeded fd =
    System.Posix.Internals.setNonBlockingFD fd True

-----------------------------------------------------------------------------
-- send & recv

send :: Socket  -- Bound/Connected Socket
     -> String  -- Data to send
     -> IO Int  -- Number of Bytes sent
send sock@(MkSocket s) xs = do
 withCStringLen xs $ \(str, len) -> do
   liftM fromIntegral $
     throwSocketErrorWaitWrite sock "send" $
        c_send s str (fromIntegral len) 0{-flags-}

sendBuf :: Socket     -- Bound/Connected Socket
        -> Ptr Word8  -- Pointer to the data to send
        -> Int        -- Length of the buffer
        -> IO Int     -- Number of Bytes sent
sendBuf sock@(MkSocket s) str len = do
   liftM fromIntegral $
     throwSocketErrorWaitWrite sock "sendBuf" $
        c_send s str (fromIntegral len) 0{-flags-}

recv :: Socket -> Int -> IO String
recv sock l = recvLen sock l >>= \ (s,_) -> return s

recvLen :: Socket -> Int -> IO (String, Int)
recvLen sock@(MkSocket s) nbytes
 | nbytes <= 0 = ioError (mkInvalidRecvArgError "Network.Socket.recv")
 | otherwise   = do
     allocaBytes nbytes $ \ptr -> do
        len <-
               throwSocketErrorWaitRead sock "recv" $
                   c_recv s ptr (fromIntegral nbytes) 0{-flags-}
        let len' = fromIntegral len
        if len' == 0
         then ioError (mkEOFError "Network.Socket.recv")
         else do
           s' <- peekCStringLen (castPtr ptr,len')
           return (s', len')

recvBuf :: Socket -> Ptr Word8 -> Int -> IO Int
recvBuf sock p l = recvLenBuf sock p l

recvLenBuf :: Socket -> Ptr Word8 -> Int -> IO Int
recvLenBuf sock@(MkSocket s) ptr nbytes
 | nbytes <= 0 = ioError (mkInvalidRecvArgError "Network.Socket.recvBuf")
 | otherwise   = do
        len <-
               throwSocketErrorWaitRead sock "recvBuf" $
                   c_recv s (castPtr ptr) (fromIntegral nbytes) 0{-flags-}
        let len' = fromIntegral len
        if len' == 0
         then ioError (mkEOFError "Network.Socket.recvBuf")
         else return len'


-----------------------------------------------------------------------------
-- Socket Properties

-- | Socket options for use with 'setSocketOption' and 'getSocketOption'.
--
-- The existence of a constructor does not imply that the relevant option
-- is supported on your system: see 'isSupportedSocketOption'
data SocketOption
    = Debug         -- ^ SO_DEBUG
    | ReuseAddr     -- ^ SO_REUSEADDR
    | Type          -- ^ SO_TYPE
    | SoError       -- ^ SO_ERROR
    | DontRoute     -- ^ SO_DONTROUTE
    | Broadcast     -- ^ SO_BROADCAST
    | SendBuffer    -- ^ SO_SNDBUF
    | RecvBuffer    -- ^ SO_RCVBUF
    | KeepAlive     -- ^ SO_KEEPALIVE
    | OOBInline     -- ^ SO_OOBINLINE
    | TimeToLive    -- ^ IP_TTL
    | MaxSegment    -- ^ TCP_MAXSEG
    | NoDelay       -- ^ TCP_NODELAY
    | Cork          -- ^ TCP_CORK
    | Linger        -- ^ SO_LINGER
    | ReusePort     -- ^ SO_REUSEPORT
    | RecvLowWater  -- ^ SO_RCVLOWAT
    | SendLowWater  -- ^ SO_SNDLOWAT
    | RecvTimeOut   -- ^ SO_RCVTIMEO
    | SendTimeOut   -- ^ SO_SNDTIMEO
    | UseLoopBack   -- ^ SO_USELOOPBACK
    | IPv6Only      -- ^ IPV6_V6ONLY
    deriving (Show, Typeable)

-- | Does the 'SocketOption' exist on this system?
isSupportedSocketOption :: SocketOption -> Bool
isSupportedSocketOption = isJust . packSocketOption

-- | For a socket option, return Just (level, value) where level is the
-- corresponding C option level constant (e.g. SOL_SOCKET) and value is
-- the option constant itself (e.g. SO_DEBUG)
-- If either constant does not exist, return Nothing.
packSocketOption :: SocketOption -> Maybe (CInt, CInt)
packSocketOption so =
  -- The Just here is a hack to disable GHC's overlapping pattern detection:
  -- the problem is if all constants are present, the fallback pattern is
  -- redundant, but if they aren't then it isn't. Hence we introduce an
  -- extra pattern (Nothing) that can't possibly happen, so that the
  -- fallback is always (in principle) necessary.
  -- I feel a little bad for including this, but such are the sacrifices we
  -- make while working with CPP - excluding the fallback pattern correctly
  -- would be a serious nuisance.
  -- (NB: comments elsewhere in this file refer to this one)
  case Just so of
#ifdef SOL_SOCKET
#ifdef SO_DEBUG
    Just Debug         -> Just ((#const SOL_SOCKET), (#const SO_DEBUG))
#endif
#ifdef SO_REUSEADDR
    Just ReuseAddr     -> Just ((#const SOL_SOCKET), (#const SO_REUSEADDR))
#endif
#ifdef SO_TYPE
    Just Type          -> Just ((#const SOL_SOCKET), (#const SO_TYPE))
#endif
#ifdef SO_ERROR
    Just SoError       -> Just ((#const SOL_SOCKET), (#const SO_ERROR))
#endif
#ifdef SO_DONTROUTE
    Just DontRoute     -> Just ((#const SOL_SOCKET), (#const SO_DONTROUTE))
#endif
#ifdef SO_BROADCAST
    Just Broadcast     -> Just ((#const SOL_SOCKET), (#const SO_BROADCAST))
#endif
#ifdef SO_SNDBUF
    Just SendBuffer    -> Just ((#const SOL_SOCKET), (#const SO_SNDBUF))
#endif
#ifdef SO_RCVBUF
    Just RecvBuffer    -> Just ((#const SOL_SOCKET), (#const SO_RCVBUF))
#endif
#ifdef SO_KEEPALIVE
    Just KeepAlive     -> Just ((#const SOL_SOCKET), (#const SO_KEEPALIVE))
#endif
#ifdef SO_OOBINLINE
    Just OOBInline     -> Just ((#const SOL_SOCKET), (#const SO_OOBINLINE))
#endif
#ifdef SO_LINGER
    Just Linger        -> Just ((#const SOL_SOCKET), (#const SO_LINGER))
#endif
#ifdef SO_REUSEPORT
    Just ReusePort     -> Just ((#const SOL_SOCKET), (#const SO_REUSEPORT))
#endif
#ifdef SO_RCVLOWAT
    Just RecvLowWater  -> Just ((#const SOL_SOCKET), (#const SO_RCVLOWAT))
#endif
#ifdef SO_SNDLOWAT
    Just SendLowWater  -> Just ((#const SOL_SOCKET), (#const SO_SNDLOWAT))
#endif
#ifdef SO_RCVTIMEO
    Just RecvTimeOut   -> Just ((#const SOL_SOCKET), (#const SO_RCVTIMEO))
#endif
#ifdef SO_SNDTIMEO
    Just SendTimeOut   -> Just ((#const SOL_SOCKET), (#const SO_SNDTIMEO))
#endif
#ifdef SO_USELOOPBACK
    Just UseLoopBack   -> Just ((#const SOL_SOCKET), (#const SO_USELOOPBACK))
#endif
#endif // SOL_SOCKET
#ifdef IPPROTO_IP
#ifdef IP_TTL
    Just TimeToLive    -> Just ((#const IPPROTO_IP), (#const IP_TTL))
#endif
#endif // IPPROTO_IP
#ifdef IPPROTO_TCP
#ifdef TCP_MAXSEG
    Just MaxSegment    -> Just ((#const IPPROTO_TCP), (#const TCP_MAXSEG))
#endif
#ifdef TCP_NODELAY
    Just NoDelay       -> Just ((#const IPPROTO_TCP), (#const TCP_NODELAY))
#endif
#ifdef TCP_CORK
    Just Cork          -> Just ((#const IPPROTO_TCP), (#const TCP_CORK))
#endif
#endif // IPPROTO_TCP
#ifdef IPPROTO_IPV6
#if HAVE_DECL_IPV6_V6ONLY
    Just IPv6Only      -> Just ((#const IPPROTO_IPV6), (#const IPV6_V6ONLY))
#endif
#endif // IPPROTO_IPV6
    _             -> Nothing

-- | Return the option level and option value if they exist,
-- otherwise throw an error that begins "Network.Socket." ++ the String
-- parameter
packSocketOption' :: String -> SocketOption -> IO (CInt, CInt)
packSocketOption' caller so = maybe err return (packSocketOption so)
 where
  err = ioError . userError . concat $ ["Network.Socket.", caller,
    ": socket option ", show so, " unsupported on this system"]

-- | Set a socket option that expects an Int value.
-- There is currently no API to set e.g. the timeval socket options
setSocketOption :: Socket
                -> SocketOption -- Option Name
                -> Int          -- Option Value
                -> IO ()
setSocketOption (MkSocket s) so v = do
   (level, opt) <- packSocketOption' "setSocketOption" so
   with (fromIntegral v) $ \ptr_v -> do
   throwSocketErrorIfMinus1_ "setSocketOption" $
       c_setsockopt s level opt ptr_v
          (fromIntegral (sizeOf (undefined :: CInt)))
   return ()


-- | Get a socket option that gives an Int value.
-- There is currently no API to get e.g. the timeval socket options
getSocketOption :: Socket
                -> SocketOption  -- Option Name
                -> IO Int        -- Option Value
getSocketOption (MkSocket s) so = do
   (level, opt) <- packSocketOption' "getSocketOption" so
   alloca $ \ptr_v ->
     with (fromIntegral (sizeOf (undefined :: CInt))) $ \ptr_sz -> do
       throwSocketErrorIfMinus1Retry "getSocketOption" $
         c_getsockopt s level opt ptr_v ptr_sz
       fromIntegral `liftM` peek ptr_v


close :: Socket -> IO ()
close (MkSocket s) = throwSocketErrorIfMinus1_ "Network.Socket.close" $ c_close s

-- | Throw an 'IOError' corresponding to the current socket error if
-- the IO action returns a result of @-1@.  Discards the result of the
-- IO action after error handling.
throwSocketErrorIfMinus1_
    :: (Eq a, Num a)
    => String  -- ^ textual description of the location
    -> IO a    -- ^ the 'IO' operation to be executed
    -> IO ()

{-# SPECIALIZE throwSocketErrorIfMinus1_ :: String -> IO CInt -> IO () #-}

-- | Throw an 'IOError' corresponding to the current socket error if
-- the IO action returns a result of @-1@, but retries in case of an
-- interrupted operation.
throwSocketErrorIfMinus1Retry
    :: (Eq a, Num a)
    => String  -- ^ textual description of the location
    -> IO a    -- ^ the 'IO' operation to be executed
    -> IO a

{-# SPECIALIZE throwSocketErrorIfMinus1Retry :: String -> IO CInt -> IO CInt #-}


throwSocketErrorIfMinus1Retry = throwErrnoIfMinus1Retry

throwSocketErrorIfMinus1_ = throwErrnoIfMinus1_

mkInvalidRecvArgError :: String -> IOError
mkInvalidRecvArgError loc = ioeSetErrorString (mkIOError
                                    InvalidArgument
                                    loc Nothing Nothing) "non-positive length"

mkEOFError :: String -> IOError
mkEOFError loc = ioeSetErrorString (mkIOError EOF loc Nothing Nothing) "end of file"


-- | Like 'throwSocketErrorIfMinus1Retry', but if the action fails with
-- @EWOULDBLOCK@ or similar, wait for the socket to be read-ready,
-- and try again.
throwSocketErrorWaitRead :: (Eq a, Num a) => Socket -> String -> IO a -> IO a
throwSocketErrorWaitRead sock name io =
    throwSocketErrorIfMinus1RetryMayBlock name
        (threadWaitRead $ fromIntegral $ sockFd sock)
        io

-- | Like 'throwSocketErrorIfMinus1Retry', but if the action fails with
-- @EWOULDBLOCK@ or similar, wait for the socket to be write-ready,
-- and try again.
throwSocketErrorWaitWrite :: (Eq a, Num a) => Socket -> String -> IO a -> IO a
throwSocketErrorWaitWrite sock name io =
    throwSocketErrorIfMinus1RetryMayBlock name
        (threadWaitWrite $ fromIntegral $ sockFd sock)
        io

throwSocketErrorIfMinus1RetryMayBlock name _ act
  = throwSocketErrorIfMinus1Retry name act

-- ---------------------------------------------------------------------------
-- foreign imports from the C library

closeFd :: CInt -> IO ()
closeFd fd = throwSocketErrorIfMinus1_ "Network.Socket.close" $ c_close fd

foreign import ccall unsafe "close"
  c_close :: CInt -> IO CInt
foreign import ccall unsafe "socket"
  c_socket :: CInt -> CInt -> CInt -> IO CInt
foreign import ccall unsafe "send"
  c_send :: CInt -> Ptr a -> CSize -> CInt -> IO CInt
foreign import ccall unsafe "recv"
  c_recv :: CInt -> Ptr CChar -> CSize -> CInt -> IO CInt
foreign import ccall unsafe "getsockopt"
  c_getsockopt :: CInt -> CInt -> CInt -> Ptr CInt -> Ptr CInt -> IO CInt
foreign import ccall unsafe "setsockopt"
  c_setsockopt :: CInt -> CInt -> CInt -> Ptr CInt -> CInt -> IO CInt

