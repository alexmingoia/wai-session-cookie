module Network.Wai.Middleware.Session
  ( withSession,
    withSession',
    session,
    Encode,
    Decode,
  )
where

import Control.Exception (displayException, throwIO)
import Control.Monad
import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (BlockCipher (..), Cipher (..), nullIV)
import Crypto.Error (eitherCryptoError)
import Data.ByteString as B (ByteString, append, concat, length, take)
import Data.ByteString.Base58
import Data.ByteString.Builder (toLazyByteString)
import qualified Data.ByteString.Lazy as BL
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.List (filter, find)
import Data.Maybe (fromMaybe)
import Data.Time.Clock (addUTCTime, getCurrentTime)
import qualified Data.Vault.Lazy as V
import Network.HTTP.Types.Header (hCookie, hSetCookie)
import Network.Wai (Middleware, Request (..), Response, mapResponseHeaders)
import System.IO.Unsafe (unsafePerformIO)
import Web.Cookie

type Encode a = a -> ByteString

type Decode a = ByteString -> Either String a

vaultKey :: V.Key (Maybe a, (Maybe a -> IO ()))
vaultKey = unsafePerformIO V.newKey
{-# NOINLINE vaultKey #-}

withSession ::
  -- | Encoder for session
  Encode a ->
  -- | Decoder for session
  Decode a ->
  -- | Secret used for encryption
  ByteString ->
  -- | Cookie name
  ByteString ->
  -- | Middleware
  Middleware
withSession encode decode secret cookieName =
  withSession' encode decode secret $
    defaultSetCookie
      { setCookieName = cookieName,
        setCookiePath = Just "/",
        setCookieHttpOnly = True,
        setCookieMaxAge = Just (365 * 24 * 60 * 60)
      }

withSession' ::
  -- | Encoder for session
  Encode a ->
  -- | Decoder for session
  Decode a ->
  -- | Secret used for encryption
  ByteString ->
  -- | Cookie settings
  SetCookie ->
  -- | Middleware
  Middleware
withSession' encode decode secret cookie app req respond = do
  sessionM <- fromCookie decode secret cookie req
  ref <- newIORef sessionM
  let secret' = padSecret secret
      store = (sessionM, writeIORef ref)
      req' = req {vault = V.insert vaultKey store (vault req)}
  app req' $ \res -> do
    sessionM' <- readIORef ref
    cookie' <- maybe (toExpiredCookie cookie) (toCookie encode secret' cookie) sessionM'
    respond $ setCookieHeader cookie' res

padSecret :: ByteString -> ByteString
padSecret s = B.append s $ B.concat (replicate (32 - B.length s) " ")

-- | Returns the session and a function to update the session.
--
-- Passing `Nothing` to the setter will clear the session.
session :: Request -> (Maybe a, (Maybe a -> IO ()))
session req =
  fromMaybe (Nothing, (pure . const ())) $ V.lookup vaultKey (vault req)

getCookie :: ByteString -> Request -> Maybe ByteString
getCookie name req =
  let headers = snd <$> filter ((==) hCookie . fst) (requestHeaders req)
   in fmap snd . find ((name ==) . fst) . join $ parseCookies <$> headers

fromCookie :: Decode a -> ByteString -> SetCookie -> Request -> IO (Maybe a)
fromCookie decode secret cookie req =
  case getCookie (setCookieName cookie) req of
    Nothing -> return Nothing
    Just cipher ->
      case decode =<< decrypt secret cipher of
        Left err -> throwIO $ userError err
        Right session -> return $ Just session

toCookie :: Encode a -> ByteString -> SetCookie -> a -> IO SetCookie
toCookie encode secret cookie session = do
  let msg = encode session
  cipher <- either (throwIO . userError) pure $ encrypt secret msg
  return $ cookie {setCookieValue = cipher}

toExpiredCookie :: SetCookie -> IO SetCookie
toExpiredCookie cookie = do
  return $
    cookie
      { setCookieValue = "",
        setCookieMaxAge = Just 0
      }

setCookieHeader :: SetCookie -> Response -> Response
setCookieHeader cookie res = mapResponseHeaders ((hSetCookie, cookieBS) :) res
  where
    cookieBS = BL.toStrict . toLazyByteString $ renderSetCookie cookie

-- Trim secret to 256 bits (32 * 8).
initCipher :: ByteString -> Either String AES256
initCipher secret =
  case eitherCryptoError (cipherInit (B.take 32 secret)) of
    Left e -> Left (displayException e)
    Right c -> Right c

encrypt :: ByteString -> ByteString -> Either String ByteString
encrypt secret msg = do
  cipher <- initCipher secret
  let cipherbs = ctrCombine cipher nullIV msg
  return $ encodeBase58 bitcoinAlphabet cipherbs

decrypt :: ByteString -> ByteString -> Either String ByteString
decrypt secret base58 = do
  cipher <- initCipher secret
  ciphertext <- maybe (Left "Failed to decode base 58") Right $ decodeBase58 bitcoinAlphabet base58
  return $ ctrCombine cipher nullIV ciphertext
