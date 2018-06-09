var BigInteger = require('bigi');
const util = require('util');
const exec = util.promisify(require('child_process').exec);

async function gitFetch() {
	const {
		stdout,
		stderr
	} = await exec('sh git-fetch.sh').catch(function (reason) {
		console.log("sadly, this failed. - " + reason);
		process.exit(0);
	});
	console.log('stdout:', stdout);
	console.log('stderr:', stderr);
};

async function gitCommit() {
	const {
		stdout,
		stderr
	} = await exec('sh git-commit.sh').catch(function (reason) {
		console.log("sadly, this failed. - " + reason);
		process.exit(0);
	});
	console.log('stdout:', stdout);
	console.log('stderr:', stderr);
};

var optionDefinitions = [{
		name: 'publicKey',
		alias: 'u',
		type: String
	},
	{
		name: 'privateKey',
		alias: 'r',
		type: String
	},
	{
		name: 'coinName',
		alias: 'c',
		type: String
	},
	{
		name: 'commitGit',
		alias: 'b',
		type: Boolean
	},
	{
		name: 'log',
		alias: 'l',
		type: Boolean
	},
	{
		name: 'help',
		alias: 'h',
		type: Boolean
	}
];

var commandLineArgs = require('command-line-args');
var options = commandLineArgs(optionDefinitions);

var SHA256 = {};
var B58base = BigInteger.valueOf(58);
var B58alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

var decodeBase58 = function (input) {
	var bi = BigInteger.valueOf(0);
	var leadingZerosNum = 0;
	for (var i = input.length - 1; i >= 0; i--) {
		var alphaIndex = B58alphabet.indexOf(input[i]);
		if (alphaIndex < 0) {
			throw "Invalid character";
		}
		/*console.log("X0:"+bi);
		console.log("X1:"+BigInteger.valueOf(alphaIndex)+" - " + alphaIndex);
		console.log("X2:"+B58base.pow(input.length - 1 - i));
		console.log("X3:"+BigInteger.valueOf(alphaIndex)
			.multiply(B58base.pow(input.length - 1 - i)));*/
		bi = bi.add(BigInteger.valueOf(alphaIndex)
			.multiply(B58base.pow(input.length - 1 - i)));
		/*				console.log("X4:"+bi);
						console.log("---");*/
		// This counts leading zero bytes
		if (input[i] == "1") leadingZerosNum++;
		else leadingZerosNum = 0;
	}
	var bytes = bi.toByteArrayUnsigned();

	// Add leading zeros
	while (leadingZerosNum-- > 0) bytes.unshift(0);

	return bytes;
};

function hexToBytes(hex) {
	for (var bytes = [], c = 0; c < hex.length; c += 2)
		bytes.push(parseInt(hex.substr(c, 2), 16));
	return bytes;
}

var wordsToBytes = function (words) {
	for (var bytes = [], b = 0; b < words.length * 32; b += 8)
		bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
	return bytes;
};

var SHA256_ = function (message, options) {
	var digestbytes = wordsToBytes(SHA256._sha256(message));
	return options && options.asBytes ? digestbytes :
		options && options.asString ? Binary.bytesToString(digestbytes) :
		util.bytesToHex(digestbytes);
};

var util = {};
util.bytesToHex = function (bytes) {
	for (var hex = [], i = 0; i < bytes.length; i++) {
		hex.push((bytes[i] >>> 4).toString(16));
		hex.push((bytes[i] & 0xF).toString(16));
	}
	return hex.join("");
};

util.bytesToWords = function (bytes) {
	for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
		words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
	return words;
};


// The core
SHA256._sha256 = function (message) {

	// Convert to byte array
	if (message.constructor == String) message = UTF8.stringToBytes(message);
	/* else, assume byte array already */

	var m = util.bytesToWords(message),
		l = message.length * 8,
		H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
			0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
		],
		w = [],
		a, b, c, d, e, f, g, h, i, j,
		t1, t2;

	// Padding
	m[l >> 5] |= 0x80 << (24 - l % 32);
	m[((l + 64 >> 9) << 4) + 15] = l;

	for (i = 0; i < m.length; i += 16) {

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		for (j = 0; j < 64; j++) {

			if (j < 16) w[j] = m[j + i];
			else {

				var gamma0x = w[j - 15],
					gamma1x = w[j - 2],
					gamma0 = ((gamma0x << 25) | (gamma0x >>> 7)) ^
					((gamma0x << 14) | (gamma0x >>> 18)) ^
					(gamma0x >>> 3),
					gamma1 = ((gamma1x << 15) | (gamma1x >>> 17)) ^
					((gamma1x << 13) | (gamma1x >>> 19)) ^
					(gamma1x >>> 10);

				w[j] = gamma0 + (w[j - 7] >>> 0) +
					gamma1 + (w[j - 16] >>> 0);

			}

			var ch = e & f ^ ~e & g,
				maj = a & b ^ a & c ^ b & c,
				sigma0 = ((a << 30) | (a >>> 2)) ^
				((a << 19) | (a >>> 13)) ^
				((a << 10) | (a >>> 22)),
				sigma1 = ((e << 26) | (e >>> 6)) ^
				((e << 21) | (e >>> 11)) ^
				((e << 7) | (e >>> 25));


			t1 = (h >>> 0) + sigma1 + ch + (K[j]) + (w[j] >>> 0);
			t2 = sigma0 + maj;

			h = g;
			g = f;
			f = e;
			e = (d + t1) >>> 0;
			d = c;
			c = b;
			b = a;
			a = (t1 + t2) >>> 0;

		}

		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;

	}

	return H;

};

// Package private blocksize
SHA256._blocksize = 16;

SHA256._digestsize = 32;


// Constants
var K = [0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
];


var decodeAddress = function (string) {
	var bytes = new Uint8Array(decodeBase58(string));
	var length = bytes.length;
	var hash = bytes.slice(0, length - 4);
	if (options.log) {
		console.log("hash:" + hash);
	}
	var sha1 = SHA256_(hash, {
		asBytes: true
	});
	if (options.log) {
		console.log("sha1:" + sha1);
	}
	var checksum = SHA256_(sha1, {
		asBytes: true
	});
	if (options.log) {

		console.log("checksum: " + checksum);
	}
	if (checksum[0] != bytes[length - 4] ||
		checksum[1] != bytes[length - 3] ||
		checksum[2] != bytes[length - 2] ||
		checksum[3] != bytes[length - 1]) {
		console.log("invalid key. :-(");
		process.exit(1);
	}

	return hash;
};


var bcs = require('bitcoinjs-lib');

var coin = {
	messagePrefix: '\x19Coin:\n',
	bip32: {
		public: 0x019da462,
		private: 0x019d9cfe
	},
	pubKeyHash: 0x00,
	scriptHash: 0xff,
	wif: 0x80
};

var generateWallet = function (coin, compression) {
	var keyPair = bcs.ECPair.makeRandom({
		network: coin,
		compression: compression
	});
	var wif = keyPair.toWIF();
	var address = keyPair.getAddress();

	return [address, wif];
};

var commandLineUsage = require('command-line-usage');

var sections = [{
		header: 'AutoWalletGeneratorGenerator',
		content: 'Automatic generator for the WalletGenerator.Net'
	},
	{
		header: 'Options',
		optionList: [{
				name: 'coinName',
				typeLabel: '{underline coin}',
				alias: 'c',
				description: 'Name of coin'
			}, {
				name: 'publicKey',
				typeLabel: '{underline key}',
				alias: 'u',
				description: 'Example public key'
			}, {
				name: 'privateKey',
				typeLabel: '{underline key}',
				alias: 'r',
				description: 'Example private key'
			},
			{
				name: 'help',
				alias: 'h',
				description: 'Print this usage guide.'
			},
			{
				name: 'log',
				alias: 'l',
				description: 'Print log'
			},
			{
				name: 'commitGit',
				alias: 'g',
				description: 'Commit GIT change'
			}
		]
	}
];
if (options.publicKey === undefined || options.privateKey === undefined || options.coinName === undefined || options.help !== undefined) {
	var usage = commandLineUsage(sections);
	console.log(usage);
	process.exit(1);
}
var coinName = options.coinName;
var publicAddress = options.publicKey;
var privateAddress = options.privateKey;
var pubKeyHash = decodeAddress(publicAddress)[0];
var pubKeyHashHex = '0x' + pubKeyHash.toString(16);
if (options.log) {
	console.log("pkh: " + pubKeyHashHex);
}
var wif = new Uint8Array(decodeBase58(privateAddress))[0];
var wifHex = '0x' + wif.toString(16);
if (options.log) {
	console.log("wif: " + wifHex);
}
coin.pubKeyHash = pubKeyHash;
coin.wif = wif;

if (options.log) {
	console.log("generating wallets for prefix determination...");
}
var prefixString = "";
for (var i = 0; i < 100; i++) {
	var gen = generateWallet(coin, false);
	var pf = gen[1][0];
	if (prefixString.indexOf(pf) < 0) {
		prefixString = prefixString + pf;
	}
}
if (prefixString.length > 1) {
	prefixString = "[" + prefixString + "]";
}

if (options.log) {
	console.log("prefix uncompressed: " + prefixString);
}

var prefixString2 = "";
for (var i = 0; i < 100; i++) {
	var gen = generateWallet(coin, true);
	var pf = gen[1][0];
	if (prefixString2.indexOf(pf) < 0) {
		prefixString2 = prefixString2 + pf;
	}
}
if (prefixString2.length > 1) {
	prefixString2 = "[" + prefixString2 + "]";
}

if (options.log) {
	console.log("prefix compressed: " + prefixString2);
}

var createCurrency = '    janin.currency.createCurrency ("' + coinName + '", ' + pubKeyHashHex + ', ' + wifHex + ', "' + prefixString + '", "' + prefixString2 + '")';

if (options.commitGit) {
	gitFetch();
	var f = fs.readFileSync("./gitsource/src/janin.currency.js")
	var janinContent = f.toString().split("\n")
	var idx = 0;
	var idxEnd = 0;
	for (var s = 0; s < janinContent.length; s++) {
		if (janinContent[s] === 'janin.currencies = [') {
			idx = s;
		}
		if (janinContent[s].includes("Testnet Bitcoin")) {
			idxEnd = s - 3;
		}
	}
	idx = idx + 1;

	var content = janinContent;
	content = content.slice(idx, idxEnd);
	content.push(createCurrency);

	content.sort(function (a, b) {
		var splA = a.split('"', 3)[1];
		if (splA !== undefined) splA = splA.toUpperCase();
		var splB = b.split('"', 3)[1];
		if (splB !== undefined) splB = splB.toUpperCase();
		//console.log("splA vs splB:" + splA + " " + splB);
		if (splA === splB) return 0;
		return splA > splB ? 1 : -1;
	});

	newContent = janinContent.slice(0, idx).join("\n") + "\n" + content.join("\n") + "\n" + janinContent.slice(idxEnd).join("\n");
	fs.writeFileSync("./janin.currency.js.new", newContent);
	gitCommit();
}

console.log("created currency: " + createCurrency);