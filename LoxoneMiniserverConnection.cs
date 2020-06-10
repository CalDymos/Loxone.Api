using Loxone.Api.Core;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Loxone.Driver.Api;
using Loxone.Api.Data;
using Loxone.Api.Data.LoxApp;
using Loxone.Api.Data.Message;
using Loxone.Driver.EventArgs;
using PureWebSockets;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace Loxone.Api {
	public enum ConnectionState {
		Connecting,
		ExchangeKeys,
		AcquireToken,
		SaveToken,
		SendEnableUpdates,
		Connected,
		Disconnected
	}

	public class LoxoneMiniserverConnection {
		private readonly string password;
		private readonly LoxoneWebApi webApi;

		public  string LoxoneUuid;
		private byte[] _aesKey;
		private byte[] _aesIv;
		private readonly PureWebSocket _webSocket;

		private ConnectionState _connectionState = ConnectionState.Disconnected;
		private byte[] _pubKey;

		private string _salt;

		private bool _encrypted = false;
		private LoxApp3Data _loxData;
		private readonly List<byte> _buffer = new List<byte>();
		private readonly object _lock = new object();

		private readonly Timer _keepAliveTimer;

		public event EventHandler<OnEventTableMessageEventArgs> OnMessage;
		public event EventHandler<System.EventArgs> OnConnectionEstablished;
		public event EventHandler<System.EventArgs> OnConnectionClosed;
		public event EventHandler<System.EventArgs> OnAppDataLoaded;

		public LoxoneMiniserverConnection(string address, int port, string username, string password, string Uuid = "bf498f26-d789-4025-a6f0-0bac6985dd64", PureWebSocketOptions socketOpts = null) {
			_keepAliveTimer = new Timer(TimeSpan.FromMinutes(4).TotalMilliseconds);
			Address = address;
			Port = port;
			Username = username;
			LoxoneUuid = Uuid;
			this.password = password;
			PureWebSocketOptions socketOptions;

			webApi = new LoxoneWebApi($"http://{address}:{port}", username, password);
			if (socketOpts != null)
			{
				socketOptions = new PureWebSocketOptions()
				{
					Proxy = socketOpts.Proxy,
					SubProtocols = socketOpts.SubProtocols,
					SendQueueLimit = socketOpts.SendQueueLimit,
					SendCacheItemTimeout = socketOpts.SendCacheItemTimeout,
					SendDelay = socketOpts.SendDelay,
					MyReconnectStrategy = socketOpts.MyReconnectStrategy,
					DebugMode = socketOpts.DebugMode,
					IgnoreCertErrors = socketOpts.IgnoreCertErrors,
					Cookies = socketOpts.Cookies,
					ClientCertificates = socketOpts.ClientCertificates,
					DisconnectWait = socketOpts.DisconnectWait,
					DebugOutput = socketOpts.DebugOutput
				};
			}
			else
			{
				socketOptions = new PureWebSocketOptions()
				{
					DebugMode = false
				};
			}
			_webSocket = new PureWebSocket($"ws://{address}:{port}/ws/rfc6455", socketOptions);
			_keepAliveTimer.Elapsed += _keepAliveTimer_Elapsed;
		}

		private void _keepAliveTimer_Elapsed(object sender, ElapsedEventArgs e) {
			if (_webSocket.State != System.Net.WebSockets.WebSocketState.Open) {
				return;
			}
			_webSocket.Send("keepalive");
		}

		public LoxApp3Data LoxData => _loxData;

		//public Task<LoxApp3Data> LoadLoxAppData() {
		//	return webApi.GetBasicAuthRequest<LoxApp3Data>("/data/LoxAPP3.json");
		//}

		public Task<LoxoneApiResponse<WriteValueResponse>> WriteValue(string uuid, object value) {
			var uriParam = "";

			if (value is bool vBool) {
				uriParam = vBool ? "on" : "off";
			} else {
				uriParam = value.ToString();
			}

			return webApi.GetRequest<WriteValueResponse>($"/jdev/sps/io/{uuid}/{uriParam}");
		}

		public Task<LoxoneApiResponse<WriteValueResponse>> ReadValue(string uuid) {			
			return webApi.GetRequest<WriteValueResponse>($"/jdev/sps/io/{uuid}");
		}

		public bool EnableStatusUpdates() {
			return _webSocket.Send(EncryptMessageForMs($"salt/{GenerateSalt()}/jdev/sps/enablebinstatusupdate", false));			
		}



		public async Task<bool> Connect() {
			try {
				_webSocket.OnStateChanged += _webSocket_OnStateChanged;
				_webSocket.OnMessage += _webSocket_OnMessage;
				_webSocket.OnClosed += _webSocket_OnClosed;
				_webSocket.OnSendFailed += _webSocket_OnSendFailed;
				_webSocket.OnData += _webSocket_OnData;

				try {
					_loxData = await webApi.GetBasicAuthRequest<LoxApp3Data>("/data/LoxAPP3.json");
					if (this.OnAppDataLoaded != null) {
						this.OnAppDataLoaded(this, new EventArgs());
					}
				} catch {
					return false;
				}
				_keepAliveTimer.Start();
				var connect = _webSocket.Connect();

				if (connect) {
					await InitConnection();
				}
				return connect;
			} catch (Exception e) {
				throw;
			}
		}

		public void Close() {
			_webSocket.OnStateChanged -= _webSocket_OnStateChanged;
			_webSocket.OnMessage -= _webSocket_OnMessage;
			_webSocket.OnClosed -= _webSocket_OnClosed;
			_webSocket.OnSendFailed -= _webSocket_OnSendFailed;
			_webSocket.OnData -= _webSocket_OnData;

			_webSocket.Disconnect();
		}

		private void _webSocket_OnData(byte[] data) {
			lock (_lock) {
				if (data == null) {
					return;
				}
				_buffer.AddRange(data);

				TryReadData();
			}
		}

		private void TryReadData() {
			if (_buffer.Count <= 0) {
				return;
			}
			// Console.WriteLine(Utility.Utils.ByteArrayToString(_buffer.ToArray()));
			if (_buffer[0] == 0x03)//check for header 
			{
				if (_buffer.Count >= 8) {
					var infoByte = _buffer[1];
					if (Utils.IsBitSet(infoByte, 7)) {
						_buffer.Clear();
						return;
					}
					var dataBuf = _buffer.ToArray().AsSpan();
					var headerData = dataBuf.Slice(0, 8);
					var header = new Header(headerData);

					if (header.Identifier == HeaderIdentifier.TextMessage) {
						//will not be transmitted as OnData 
						var nextData = dataBuf.Slice(8, _buffer.Count - 8);

						_buffer.Clear();
						_buffer.AddRange(nextData.ToArray());
						return;
					}

					if (_buffer.Count >= header.DataLength + 8) {
						//get my data array out of the buffer
						var dataBuffer = dataBuf.Slice(8, (int)header.DataLength);

						//get the next data out of the buffer
						var nextData = dataBuf.Slice((int)header.DataLength + 8, _buffer.Count - ((int)header.DataLength + 8));
						var msg = BinaryMessage.GenerateBinaryMessage(header, dataBuffer);

						//clear the buffer
						_buffer.Clear();

						//fill the next data in the buffer
						_buffer.AddRange(nextData.ToArray());

						if (msg != null) {
							OnMessage?.Invoke(this, new OnEventTableMessageEventArgs(msg));
						}

					}
				}
			}
		}

		public static RSAParameters ToRSAParameters(RsaKeyParameters rsaKey) {
			RSAParameters rp = new RSAParameters();
			rp.Modulus = rsaKey.Modulus.ToByteArrayUnsigned();
			if (rsaKey.IsPrivate)
				rp.D = rsaKey.Exponent.ToByteArrayUnsigned();
			else
				rp.Exponent = rsaKey.Exponent.ToByteArrayUnsigned();
			return rp;
		}

		private void _webSocket_OnSendFailed(string data, Exception ex) {
			throw new NotImplementedException();
		}

		private void _webSocket_OnClosed(System.Net.WebSockets.WebSocketCloseStatus reason) {
			OnConnectionClosed?.Invoke(this, System.EventArgs.Empty);
		}

		private void _webSocket_OnMessage(string message) {
			if (_encrypted) {
				var encrypted = DecryptMessage(message);
				var baseMessage = JsonConvert.DeserializeObject<LoxoneApiResponse<LoxoneApiResponseLL>>(encrypted);

				if (baseMessage.Data.Code == 200) {
					if (_connectionState == ConnectionState.AcquireToken) {
						var data = JsonConvert.DeserializeObject<LoxoneApiResponse<GetKeyResponseLL>>(encrypted);

						var pwHash = SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes($"{password}:{data.Data.Value.Salt}")).ToHex(true);
						var hash = $"{Username}:{pwHash}".CalculateHmacSha1(Utils.StringToByteArray(data.Data.Value.Key));

						var cmd = $"salt/{GenerateSalt()}/jdev/sys/gettoken/{hash}/{Username}/4/{LoxoneUuid}/LoxBridge";

						var msg = EncryptMessageForMs(cmd);
						_connectionState = ConnectionState.SaveToken;
						_webSocket.Send(msg);
					} else if (_connectionState == ConnectionState.SaveToken) {
						var data = JsonConvert.DeserializeObject<LoxoneApiResponse<TokenResponseLL>>(encrypted);
						_connectionState = ConnectionState.SendEnableUpdates;
						_encrypted = false;
						_webSocket.Send(EncryptMessageForMs($"salt/{GenerateSalt()}/jdev/sps/enablebinstatusupdate", false)); 

					}
				} else {
					//TODO: specify why
					OnConnectionClosed?.Invoke(this, System.EventArgs.Empty);
				}
			} else {

				var baseMessage = JsonConvert.DeserializeObject<LoxoneApiResponse<LoxoneApiResponseLL>>(message);
				if (baseMessage.Data.Code == 200) {
					_encrypted = true;
					if (_connectionState == ConnectionState.ExchangeKeys) {

						var data = JsonConvert.DeserializeObject<LoxoneApiResponse<EncryptedMessageResponse>>(message);
						var decryptedMessage = DecryptMessage(data.Data.Value);

						_connectionState = ConnectionState.AcquireToken;
						AcquireToken();
					} else if (_connectionState == ConnectionState.SendEnableUpdates) {
						//do nothing
					}
				}
			}
		}

		private string GenerateSalt() {
			if (_salt == null) {
				SecureRandom random = new SecureRandom();
				var byteArray = new byte[2];
				random.NextBytes(byteArray);
				_salt = byteArray.ToHex(false);
			}
			return _salt;
		}

		private void AcquireToken() {
			var cmd = $"salt/{GenerateSalt()}/jdev/sys/getkey2/{Username}";
			var encrypted = EncryptMessageForMs(cmd);

			_webSocket.Send(encrypted);

		}

		private byte[] PrepareEncrypt(string payload, int outputBlockSize) {
			var byteArray = Encoding.UTF8.GetBytes(payload);
			if (byteArray.Length % outputBlockSize != 0) {
				var byteSize = Math.Ceiling((double)byteArray.Length / outputBlockSize);
				var newByteArray = new byte[(int)byteSize * outputBlockSize];

				Array.Copy(byteArray, newByteArray, byteArray.Length);
				return newByteArray;
			}
			return byteArray;
		}

		private string EncryptMessageForMs(string payload, bool sendsResponse = true) {
			using (var aes = Aes.Create()) {
				aes.Padding = PaddingMode.None;
				aes.Mode = CipherMode.CBC;
				using (ICryptoTransform encryptor = aes.CreateEncryptor(_aesKey, _aesIv)) {
					using (var memoryStream = new MemoryStream()) {
						using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
							byte[] buffer = PrepareEncrypt(payload, encryptor.OutputBlockSize);
							cryptoStream.Write(buffer,0 ,Buffer.ByteLength(buffer));
						}
						var msFnc = "fenc";
						if (!sendsResponse) {
							msFnc = "enc";
						}
						return $"jdev/sys/{msFnc}/{WebUtility.UrlEncode(Convert.ToBase64String(memoryStream.ToArray()))}";
					}
				}
			}
		}

		private string DecryptMessage(string message) {
			try {
				var byteArray = Convert.FromBase64String(message);
				using (var aes = Aes.Create()) {
					aes.Padding = PaddingMode.None;
					aes.Mode = CipherMode.CBC;
					using (ICryptoTransform encryptor = aes.CreateDecryptor(_aesKey, _aesIv)) {
						using (var memoryStream = new MemoryStream()) {
							using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
								cryptoStream.Write(byteArray, 0 , Buffer.ByteLength(byteArray));
							}

							return Encoding.UTF8.GetString(memoryStream.ToArray());
						}
					}
				}
			} catch (System.FormatException formatErr) {
				return message;

			}
		}

		public byte[] GenerateAesKey(string key) {
			byte[] salt = new byte[128 / 8];
			using (var rng = RandomNumberGenerator.Create()) {
				rng.GetBytes(salt);
			}

			// derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
			var hashed = KeyDerivation.Pbkdf2(
					key,
					salt,
					KeyDerivationPrf.HMACSHA256,
					50, 256 / 8);
			return hashed;
		}



		private async void _webSocket_OnStateChanged(System.Net.WebSockets.WebSocketState newState, System.Net.WebSockets.WebSocketState prevState) {
			if (newState == System.Net.WebSockets.WebSocketState.Open) {

			}
		}

		private async Task InitConnection() {
			OnConnectionEstablished?.Invoke(this, System.EventArgs.Empty);

			var publicKey = await webApi.GetRequest<GetPublicKeyResponse>("jdev/sys/getPublicKey"); ;
			_pubKey = Convert.FromBase64String(publicKey.Data.PublicKey.Replace("-----END CERTIFICATE-----", "").Replace("-----BEGIN CERTIFICATE-----", ""));
			string stringDataToEncrypt;

			SecureRandom random = new SecureRandom();
			_aesKey = GenerateAesKey(LoxoneUuid);

			_aesIv = new byte[128 / 8];
			random.NextBytes(_aesIv);

			stringDataToEncrypt = $"{_aesKey.ToHex(false)}:{_aesIv.ToHex(false)}";

			Asn1Object obj = Asn1Object.FromByteArray(_pubKey);
			DerSequence publicKeySequence = (DerSequence)obj;

			DerBitString encodedPublicKey = (DerBitString)publicKeySequence[1];
			DerSequence publicKeyDer = (DerSequence)Asn1Object.FromByteArray(encodedPublicKey.GetBytes());

			DerInteger modulus = (DerInteger)publicKeyDer[0];
			DerInteger exponent = (DerInteger)publicKeyDer[1];

			RsaKeyParameters keyParameters = new RsaKeyParameters(false, modulus.PositiveValue, exponent.PositiveValue);
			var encryptEngine = new Pkcs1Encoding(new RsaEngine());
			encryptEngine.Init(true, keyParameters);

			byte[] dataToEncrypt = Encoding.UTF8.GetBytes(stringDataToEncrypt);
			byte[] encryptedData = encryptEngine.ProcessBlock(dataToEncrypt, 0, dataToEncrypt.Length);

			var publicKeySelf = Convert.ToBase64String(encryptedData);
			_connectionState = ConnectionState.ExchangeKeys;

			_webSocket.Send($"jdev/sys/keyexchange/{publicKeySelf}");
		}

		public string Address { get; }
		public int Port { get; }
		public string Username { get; }
	}
}
