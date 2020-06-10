using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace Loxone.Api.Data.LoxApp {
	public class LoxApp3Data {
		public DateTime LastModified { get; set; }

		[JsonProperty("msInfo")]
		public MiniserverInfo MiniserverInfo { get; set; }


		[JsonProperty("globalStates")]
		public Dictionary<string, string> GlobalStates { get; set; }

		[JsonProperty("operatingModes")]
		public Dictionary<string, string> OperatingModes { get; set; }


		[JsonProperty("rooms")]
		public Dictionary<string, LoxoneRoom> Rooms { get; set; }

		[JsonProperty("cats")]
		public Dictionary<string, LoxoneCategory> Categories { get; set; }

		[JsonProperty("controls")]
		public Dictionary<string, LoxoneControl> Controls { get; set; }
	}
}
