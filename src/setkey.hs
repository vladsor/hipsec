{-# LANGUAGE DeriveDataTypeable    #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Main (main) where

import           Control.Monad
import qualified Data.ByteString     as BS
import qualified Data.ByteString.Char8     as BSC
import qualified Data.ByteString.Lazy     as LBS
import           Network.Security.Message
import           Network.Security.PFKey
import           System.Console.CmdArgs
import           Control.Applicative
import           Data.Binary              (decode, encode)
import           Data.Bits
import           Data.Char
import           Network.Socket
import           System.IO                (stdin)
import qualified Text.Parsec              as P
import qualified Text.Parsec.Prim         as P
import Data.Time.Clock

data SetKey =
  SetKey
  { dump   :: Bool
  , flush  :: Bool
  , policy :: Bool
  , cmds   :: Bool
  } deriving (Show, Data, Typeable)

setkey =
  SetKey
  { dump = def &= name "D"  &= help
           "Dump the SAD entries.  If -P is also specified, the SPD entries are dumped.  If -p is specified, the ports are displayed."
  , flush = def &= name "F" &= help
            "Flush the SAD entries.  If -P is also specified, the SPD entries are flushed."
  ,policy = def &= name "P" &= help "Policy entries"
  ,cmds = def &= name "c" &= help "read commands from stdin"
  }
  &=
  verbosity &=
  help "" &=
  summary "F-IPSec-Tools v0.0.0, (C) Vladimir Sorokin 2011" &=
  details ["",""
          ,"",""]

main :: IO ()
main = do
  opts <- cmdArgs setkey

  case policy opts of
    True -> do
      when (dump opts) $ do
        s <- pfkey_open
        pfkey_send_spddump s
        iterateM_ $ do
          res <- pfkey_recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              pfkey_spd_dump msg
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
        pfkey_close s
      return ()
      when (flush opts) $ do
        putStrLn "SPD Flush"
        s <- pfkey_open
        pfkey_send_spdflush s
        pfkey_close s
    False -> do
      when (dump opts) $ do
        s <- pfkey_open
        pfkey_send_dump s SATypeUnspec
        iterateM_ $ do
          res <- pfkey_recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              ct <- getCurrentTime
              putStrLn $ pfkey_sa_dump msg ct
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
        pfkey_close s
      when (flush opts) $ do
        putStrLn "SAD Flush"
        s <- pfkey_open
        doCommand s CommandFlush
        pfkey_close s

  when (cmds opts) $ do
    putStrLn "Read commands"
    raw <- getContents
    case (P.parse tokenize "" raw) of
      Left err -> print err
      Right xs -> do
        print xs
        let xs' = filter (\i -> case i of
              TokenComment _ -> False
              _ -> True) xs
        case (P.parse parser "" xs') of
          Left err' -> print err'
          Right cmds -> do
            print cmds
            s <- pfkey_open
            pfkey_send_register s SATypeUnspec
            pfkey_recv_register s
            mapM_ (doCommand s) cmds
            pfkey_close s

doCommand :: PfSocket -> Command -> IO ()
doCommand s CommandFlush = pfkey_send_flush s SATypeUnspec
doCommand s CommandDump = do
        pfkey_send_dump s SATypeUnspec
        iterateM_ $ do
          res <- pfkey_recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              ct <- getCurrentTime
              putStrLn $ pfkey_sa_dump msg ct
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s CommandSPDFlush = pfkey_send_flush s SATypeUnspec
doCommand s CommandSPDDump = do
        pfkey_send_spddump s
        iterateM_ $ do
          res <- pfkey_recv s
          case res of
            Nothing -> print "Nothing\n" >> return False
            Just msg -> do
              print $ "Message" ++ show msg ++ "\n"
              pfkey_spd_dump msg
              return $ (msgErrno msg == 0) && (msgSeq msg /= 0)
doCommand s (CommandAdd src dst proto spi encAlg encKey authAlg authKey compAlg) =
  pfkey_send_add s proto IPSecModeAny src dst spi 0 0 authAlg authKey encAlg encKey 0 Nothing Nothing 0
doCommand s (CommandGet src dst proto spi) =
  pfkey_send_get s proto src dst spi
doCommand s (CommandDelete src dst proto spi) =
  pfkey_send_delete s proto src dst spi
doCommand s (CommandDeleteAll src dst proto) =
  pfkey_send_delete_all s proto src dst
doCommand s (CommandSPDAdd (Address _ prefs src) (Address _ prefd dst) upper label policy) =
  pfkey_send_spdadd' s src prefs dst prefd upper policy 0
doCommand s (CommandSPDAddTagged tag policy) = undefined
doCommand s (CommandSPDDelete (Address _ prefs src) (Address _ prefd dst) upper policy) =
  pfkey_send_spddelete s src prefs dst prefd upper policy 0

data Token = Token { tknString :: String }
           | TokenNumber { tknNumber :: Int }
           | TokenHexString { tknHexString :: String }
           | TokenQuotedString { tknQuotedString :: String }
           | TokenEOC
           | TokenSlash
           | TokenSqBrOpen
           | TokenSqBrClose
           | TokenDot
           | TokenComment { tknComment :: String }
           deriving (Eq, Show)

separator = P.many1 (P.oneOf " \t\n")
tokenize = P.many $ do
  P.optionMaybe separator
  tkn <- P.choice
         [ P.char ';' >> return TokenEOC
         , P.char '#' >> P.many (P.noneOf "\n") >>= return . TokenComment
         , P.char '-' >> return (Token "-")
         , P.char '/' >> return TokenSlash
         , P.char '[' >> return TokenSqBrOpen
         , P.char ']' >> return TokenSqBrClose
         , P.char '.' >> return TokenDot
         , P.between (P.char '"') (P.char '"') (liftM TokenQuotedString $ P.many (P.noneOf "\""))
         , P.char '0' >> ((P.oneOf "xX" >> (liftM TokenHexString $ P.many1 P.hexDigit)) <|>
                         (P.many1 P.digit >>= return . TokenNumber . (foldl (\a b -> a * 10 + digitToInt b) 0)))
         , P.many1 P.digit >>= return . TokenNumber . (foldl (\a b -> a * 10 + digitToInt b) 0)
         , P.many1 (P.noneOf " \t\n;#/[].\"") >>= return . Token
         ]
  P.optionMaybe separator
  return tkn

satisfy :: P.Stream s m Token => (Token -> Bool) -> P.ParsecT s u m Token
satisfy f = P.tokenPrim (\c -> show c) (\pos _c _cs -> P.incSourceColumn pos 1)
                      (\c -> if f c then Just c else Nothing)

token :: P.Stream s m Token => String -> P.ParsecT s u m String
token str = (satisfy ( == (Token str))) >>= return . tknString

tokenString :: P.Stream s m Token => P.ParsecT s u m String
tokenString = (satisfy f) >>= return . tknString
  where
    f (Token _) = True
    f _ = False

tokenQuotedString :: P.Stream s m Token => P.ParsecT s u m String
tokenQuotedString = (satisfy f) >>= return . tknQuotedString
  where
    f (TokenQuotedString _) = True
    f _ = False

tokenHexString :: P.Stream s m Token => P.ParsecT s u m String
tokenHexString = (satisfy f) >>= return . tknHexString
  where
    f (TokenHexString _) = True
    f _ = False

tokenNumber :: P.Stream s m Token => P.ParsecT s u m Int
tokenNumber = liftM tknNumber (satisfy f) <|> liftM (foldl (\a b -> a * 16 + digitToInt b) 0) tokenHexString
  where
    f (TokenNumber _) = True
    f _ = False

tokenEOC :: P.Stream s m Token => P.ParsecT s u m ()
tokenEOC = (satisfy (== TokenEOC)) >> return ()

tokenSlash :: P.Stream s m Token => P.ParsecT s u m String
tokenSlash = (satisfy f) >>= return . tknString
  where
    f TokenSlash = True
    f _ = False

tokenSqBrOpen :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrOpen = (satisfy f) >> return ()
  where
    f TokenSqBrOpen = True
    f _ = False

tokenSqBrClose :: P.Stream s m Token => P.ParsecT s u m ()
tokenSqBrClose = (satisfy f) >> return ()
  where
    f TokenSqBrClose = True
    f _ = False

tokenDot :: P.Stream s m Token => P.ParsecT s u m ()
tokenDot = (satisfy f) >> return ()
  where
    f TokenDot = True
    f _ = False

tokenKey :: P.Stream s m Token => P.ParsecT s u m Key
tokenKey = liftM (\b -> Key (8 * BS.length b) b) $ (liftM BSC.pack tokenQuotedString) <|> (liftM (BS.pack . fmap (fromIntegral . digitToInt)) tokenHexString)

cmdFlush :: P.Stream s m Token => P.ParsecT s u m Command
cmdFlush = token "flush" >> return CommandFlush

cmdDump :: P.Stream s m Token => P.ParsecT s u m Command
cmdDump = token "dump" >> return CommandDump

cmdSPDFlush :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDFlush = token "spdflush" >> return CommandSPDFlush

cmdSPDDump :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDDump = token "spddump" >> return CommandSPDDump

parser =
  P.many1 (do
              cmd <- P.choice
                     [ cmdFlush
                     , cmdDump
                     , cmdSPDFlush
                     , cmdSPDDump
                     , cmdAdd
                     , cmdGet
                     , cmdDelete
                     , cmdDeleteAll
                     , cmdSPDAdd
                     , cmdSPDDelete
                     ]
              tokenEOC
              return cmd)


cmdAdd = do
  token "add"
  addSrc <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  addDst <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  addProto <- liftM read tokenString
  addSPI <- tokenNumber
  token "-"
  token "E"
  addEncAlg <- liftM read tokenString
  addEncKey <- tokenKey
  token "-"
  token "A"
  addAuthAlg <- liftM read tokenString
  addAuthKey <- tokenKey
  let addCompAlg = CompAlgNone

  return CommandAdd{..}

cmdGet = do
  token "get"
  getSrc <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  getDst <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  getProto <- liftM read tokenString
  getSPI <- liftM read tokenString
  return CommandGet{..}

cmdDelete = do
  token "delete"
  deleteSrc <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  deleteDst <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  deleteProto <- liftM read tokenString
  deleteSPI <- liftM read tokenString
  return CommandDelete{..}

cmdDeleteAll = do
  token "deleteall"
  deleteAllSrc <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  deleteAllDst <- liftM (Address 0 32 . SockAddrInet 0) tokenIP
  deleteAllProto <- liftM read tokenString
  return CommandDeleteAll{..}

tokenIP :: P.Stream s m Token => P.ParsecT s u m HostAddress
tokenIP = do
  v1 <- tokenNumber
  tokenDot
  v2 <- tokenNumber
  tokenDot
  v3 <- tokenNumber
  tokenDot
  v4 <- tokenNumber
  return $ fromIntegral $ v1 .|. v2 `shift` 8 .|. v3 `shift` 16 .|. v4 `shift` 24

tokenPolicy :: P.Stream s m Token => P.ParsecT s u m Policy
tokenPolicy = do
  policyDir <- liftM read tokenString
  policyType <- liftM read tokenString
  ipsecreqProto <- liftM read tokenString
  tokenSlash
  ipsecreqMode <- liftM read tokenString
  tokenSlash
  ipsecreqAddrs <- P.optionMaybe $ do
    src <- tokenIP
    token "-"
    dst <- tokenIP
    return (SockAddrInet 0 src, SockAddrInet 0 dst)
  tokenSlash

  ipsecreqLevel <- liftM read tokenString

  let policyId = 0
  let policyPriority = 0
  let ipsecreqReqId = 0
  let policyIPSecRequests = return IPSecRequest{..}
  return Policy{..}

tokenAddressRange :: P.Stream s m Token => P.ParsecT s u m Address
tokenAddressRange = do
  ip <- tokenIP
  P.choice [ do
                return $ Address { addressProto = 0
                                 , addressPrefixLen = 32
                                 , addressAddr = SockAddrInet 0 ip
                                 }
           , do
                tokenSlash
                pref <- tokenNumber
                return undefined
           , do
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return undefined
           , do
                tokenSlash
                pref <- tokenNumber
                tokenSqBrOpen
                port <- tokenNumber
                tokenSqBrClose
                return undefined
           ]

cmdSPDAdd :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDAdd = do
  token "spdadd"
  spdAddSrcRange <- tokenAddressRange
  spdAddDstRange <- tokenAddressRange
  spdAddUpperSpec <- liftM read tokenString
  token "-"
  token "P"
  let spdAddLabel = Nothing
  spdAddPolicy <- tokenPolicy
  return CommandSPDAdd{..}

cmdSPDDelete :: P.Stream s m Token => P.ParsecT s u m Command
cmdSPDDelete = do
  token "spddelete"
  spdDeleteSrcRange <- tokenAddressRange
  spdDeleteDstRange <- tokenAddressRange
  spdDeleteUppperspec <- liftM read tokenString
  token "-"
  token "P"
  let spdAddLabel = Nothing
  spdDeletePolicy <- tokenPolicy
  return CommandSPDDelete{..}

data Command
  = CommandFlush
  | CommandDump
  | CommandSPDFlush
  | CommandSPDDump
  | CommandAdd
    { addSrc     :: Address
    , addDst     :: Address
    , addProto   :: SAType
    , addSPI     :: Int
    , addEncAlg  :: EncAlg
    , addEncKey  :: Key
    , addAuthAlg :: AuthAlg
    , addAuthKey :: Key
    , addCompAlg :: CompAlg
    }
  | CommandGet
    { getSrc   :: Address
    , getDst   :: Address
    , getProto :: SAType
    , getSPI   :: Int
    }
  | CommandDelete
    { deleteSrc   :: Address
    , deleteDst   :: Address
    , deleteProto :: SAType
    , deleteSPI   :: Int
    }
  | CommandDeleteAll
    { deleteAllSrc   :: Address
    , deleteAllDst   :: Address
    , deleteAllProto :: SAType
    }
  | CommandSPDAdd
    { spdAddSrcRange  :: Address
    , spdAddDstRange  :: Address
    , spdAddUpperSpec :: IPProto
    , spdAddLabel     :: Maybe String
    , spdAddPolicy    :: Policy
    }
  | CommandSPDAddTagged
    { spdAddTaggedTag    :: String
    , spdAddTaggedPolicy :: String
    }
  | CommandSPDDelete
    { spdDeleteSrcRange   :: Address
    , spdDeleteDstRange   :: Address
    , spdDeleteUppperspec :: IPProto
    , spdDeletePolicy  :: Policy
    }
  deriving (Eq, Show)

