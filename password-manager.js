"use strict";

const {decode} = require("punycode");
/********* External Imports ********/

const {
	stringToBuffer,
	bufferToString,
	encodeBuffer,
	decodeBuffer,
	getRandomBytes,
} = require("./lib");
const {subtle} = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
	/**
	 * Initializes the keychain using the provided information. Note that external
	 * users should likely never invoke the constructor directly and instead use
	 * either Keychain.init or Keychain.load.
	 * Arguments:
	 *  You may design the constructor with any parameters you would like.
	 * Return Type: void
	 */
	constructor(kvs, masterKey, aesKey, hmacKey, ivs, salt, encpass) {
		this.data = {
			/* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
			kvs: kvs,
			ivs: ivs,
			salt: salt,
			encpass: encpass,
		};
		this.secrets = {
			/* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
			masterKey: masterKey,
			aesKey: aesKey,
			hmacKey: hmacKey,
		};
	}

	/**
	 * Helper function to derive a master key from pass and salt using PBKDF2.
	 */

	static async deriveKeys(password, salt) {
		let rawKey = await subtle.importKey(
			"raw",
			stringToBuffer(password),
			"PBKDF2",
			false,
			["deriveKey"]
		);
		let masterKey = await subtle.deriveKey(
			{
				name: "PBKDF2",
				salt: salt,
				hash: "SHA-256",
				iterations: PBKDF2_ITERATIONS,
			},
			rawKey,
			{name: "HMAC", hash: "SHA-256"},
			false,
			["sign", "verify"]
		);

		// get a random key by evaluating HMAC at arbitrary value
		let hmacKeyMaterial = await subtle.sign(
			"HMAC",
			masterKey,
			stringToBuffer("arbitrary value 1")
		);
		let aesKeyMaterial = await subtle.sign(
			"HMAC",
			masterKey,
			stringToBuffer("arbitrary value 2")
		);

		// derive aes key and hmac key from master key
		let hmacKey = await subtle.importKey(
			"raw",
			hmacKeyMaterial,
			{name: "HMAC", hash: "SHA-256"},
			true,
			["sign", "verify"]
		);
		let aesKey = await subtle.importKey(
			"raw",
			aesKeyMaterial,
			"AES-GCM",
			true,
			["encrypt", "decrypt"]
		);

		// encrypt password with hmac
		let encpass = await subtle.sign("HMAC", hmacKey, stringToBuffer(password));

		return [masterKey, aesKey, hmacKey, encpass];
	}

	/**
	 * Creates an empty keychain with the given password. Also generates necessary keys.
	 *
	 * Arguments:
	 *   password: string
	 * Return Type: void
	 */
	static async init(password) {
		// create master key from password
		let salt = getRandomBytes(16);
		let masterKey, aesKey, hmacKey, encpass;
		[masterKey, aesKey, hmacKey, encpass] = await this.deriveKeys(
			password,
			salt
		);
		salt = encodeBuffer(salt);
		encpass = encodeBuffer(encpass);

		return new Keychain({}, masterKey, aesKey, hmacKey, {}, salt, encpass);
	}

	/**
	 * Loads the keychain state from the provided representation (repr). The
	 * repr variable will contain a JSON encoded serialization of the contents
	 * of the KVS (as returned by the dump function). The trustedDataCheck
	 * is an *optional* SHA-256 checksum that can be used to validate the
	 * integrity of the contents of the KVS. If the checksum is provided and the
	 * integrity check fails, an exception should be thrown. You can assume that
	 * the representation passed to load is well-formed (i.e., it will be
	 * a valid JSON object).Returns a Keychain object that contains the data
	 * from repr.
	 *
	 * Arguments:
	 *   password:           string
	 *   repr:               string
	 *   trustedDataCheck: string
	 * Return Type: Keychain
	 */
	static async load(password, repr, trustedDataCheck) {
		let contentsObj = JSON.parse(repr);

		// attack #3 (rollback attack): need trustedDataCheck
		if (trustedDataCheck !== undefined) {
			let checksum2 = decodeBuffer(trustedDataCheck);
			let checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
			if (bufferToString(checksum) !== bufferToString(checksum2)) {
				throw "Checksum mismatch!";
			}
		}

		// create new keychain
		let newKeychain = await Keychain.init(password);
		newKeychain.data.kvs = contentsObj.kvs;
		newKeychain.data.ivs = contentsObj.ivs;
		newKeychain.data.salt = contentsObj.salt;

		// replace the keys
		let masterKey, aesKey, hmacKey;
		[masterKey, aesKey, hmacKey] = await this.deriveKeys(
			password,
			decodeBuffer(contentsObj.salt)
		);
		newKeychain.secrets.masterKey = masterKey;
		newKeychain.secrets.aesKey = aesKey;
		newKeychain.secrets.hmacKey = hmacKey;

		// check if the password is correct
		let encpass = await subtle.sign("HMAC", hmacKey, stringToBuffer(password));
		if (
			bufferToString(encpass) !==
			bufferToString(decodeBuffer(contentsObj.encpass))
		) {
			throw "Password mismatch!";
		}

		// check if data has been tampered with by trying to decrypt
		for (let k in contentsObj.kvs) {
			let iv = decodeBuffer(contentsObj.ivs[k]);
			let value = decodeBuffer(contentsObj.kvs[k]);
			try {
				await subtle.decrypt(
					{
						name: "AES-GCM",
						iv: iv,
						additionalData: stringToBuffer(decodeBuffer(k)),
					},
					aesKey,
					value
				);
			} catch (e) {
				throw "Tampering detected!";
			}
		}

		return newKeychain;
	}

	/**
	 * Returns a JSON serialization of the contents of the keychain that can be
	 * loaded back using the load function. The return value should consist of
	 * an array of two strings:
	 *   arr[0] = JSON encoding of password manager
	 *   arr[1] = SHA-256 checksum (as a string)
	 * As discussed in the handout, the first element of the array should contain
	 * all of the data in the password manager. The second element is a SHA-256
	 * checksum computed over the password manager to preserve integrity.
	 *
	 * Return Type: array
	 */
	async dump() {
		let contents = JSON.stringify(this.data);
		let checksum = await subtle.digest("SHA-256", stringToBuffer(contents));
		return [contents, encodeBuffer(checksum)];
	}

	/**
	 * Fetches the data (as a string) corresponding to the given domain from the KVS.
	 * If there is no entry in the KVS that matches the given domain, then return
	 * null.
	 *
	 * Arguments:
	 *   name: string
	 * Return Type: Promise<string>
	 */
	async get(name) {
		let domain = await subtle.sign(
			"HMAC",
			this.secrets.hmacKey,
			stringToBuffer(name)
		);

		let encval = this.data.kvs[encodeBuffer(domain)];
		if (encval === undefined) {
			return null;
		}
		let iv = this.data.ivs[encodeBuffer(domain)];

		let value = await subtle.decrypt(
			{
				name: "AES-GCM",
				iv: decodeBuffer(iv),
				additionalData: stringToBuffer(domain),
			},
			this.secrets.aesKey,
			decodeBuffer(encval)
		);

		// remove padding
		value = bufferToString(value).replace(/0+$/, "");

		return bufferToString(value);
	}

	/**
	 * Inserts the domain and associated data into the KVS. If the domain is
	 * already in the password manager, this method should update its value. If
	 * not, create a new entry in the password manager.
	 *
	 * Arguments:
	 *   name: string
	 *   value: string
	 * Return Type: void
	 */
	async set(name, value) {
		// attack #1 (length attack): pad the value to max length
		if (value.length > MAX_PASSWORD_LENGTH) {
			throw "Password too long!";
		}
		value = value.padEnd(MAX_PASSWORD_LENGTH, "0");

		// encrypt and store in kvs
		let iv = getRandomBytes(12);
		let domain = await subtle.sign(
			"HMAC",
			this.secrets.hmacKey,
			stringToBuffer(name)
		);

		// attack #2 (swap attack): add identifier for each domain
		let encvalue = await subtle.encrypt(
			{name: "AES-GCM", iv: iv, additionalData: stringToBuffer(domain)},
			this.secrets.aesKey,
			stringToBuffer(value)
		);
		this.data.kvs[encodeBuffer(domain)] = encodeBuffer(encvalue);
		this.data.ivs[encodeBuffer(domain)] = encodeBuffer(iv);
	}

	/**
	 * Removes the record with name from the password manager. Returns true
	 * if the record with the specified name is removed, false otherwise.
	 *
	 * Arguments:
	 *   name: string
	 * Return Type: Promise<boolean>
	 */
	async remove(name) {
		let domain = await subtle.sign(
			"HMAC",
			this.secrets.hmacKey,
			stringToBuffer(name)
		);

		if (this.data.kvs[encodeBuffer(domain)] === undefined) {
			return false;
		}
		delete this.data.kvs[encodeBuffer(domain)];
		return true;
	}
}

module.exports = {Keychain};
