//----------------------------------
// Name: CredentialTest.js
// Author: Tan Teik Guan (tanteikg@gmail.com)
// Related Paper: Securing Password Authentication for Web-based Applications (https://arxiv.org/abs/2011.06257)
// Date: April 2022
//
// Copyright Tan Teik Guan 2022. All rights reserved
//-----------------------------------

const secp256k1 = require('secp256k1');
const { randomBytes } = require('crypto');
const crypto = require('crypto');

const pbkdf2 = require('pbkdf2');

var date = new Date();
var T = date.getTime();

const Password = "12345678";
const UserID = "userABC";
const URL = "www.test.com/ServerChallenge/ClientRandom";
const Challenge = "www.test.com/ClientRandom";
const Cert = "-----BEGIN CERTIFICATE-----MIIEFzCCAv+gAwIBAgIQB/LzXIeod6967+lHmTUlvTANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBDQTAeFw0yMTA0MTQwMDAwMDBaFw0zMTA0MTMyMzU5NTlaMFYxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxMDAuBgNVBAMTJ0RpZ2lDZXJ0IFRMUyBIeWJyaWQgRUNDIFNIQTM4NCAyMDIwIENBMTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMEbxppbmNmkKaDp1AS12+umsmxVwP/tmMZJLwYnUcu/cMEFesOxnYeJuq20ExfJqLSDyLiQ0cx0NTY8g3KwtdD3ImnI8YDEe0CPz2iHJlw5ifFNkU3aiYvkA8ND5b8vc6OCAYIwggF+MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFAq8CCkXjKU5bXoOzjPHLrPt+8N6MB8GA1UdIwQYMBaAFAPeUDVW0Uy7ZvCj4hsbw5eyPdFVMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RDQS5jcnQwQgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdENBLmNybDA9BgNVHSAENjA0MAsGCWCGSAGG/WwCATAHBgVngQwBATAIBgZngQwBAgEwCAYGZ4EMAQICMAgGBmeBDAECAzANBgkqhkiG9w0BAQwFAAOCAQEAR1mBf9QbH7Bx9phdGLqYR5iwfnYr6v8ai6wms0KNMeZK6BnQ79oU59cUkqGS8qcuLa/7Hfb7U7CKP/zYFgrpsC62pQsYkDUmotr2qLcy/JUjS8ZFucTP5Hzu5sn4kL1y45nDHQsFfGqXbbKrAjbYwrwsAZI/BKOLdRHHuSm8EdCGupK8JvllyDfNJvaGEwwEqonleLHBTnm8dqMLUeTF0J5q/hosVq4GNiejcxwIfZMy0MJEGdqN9A57HSgDKwmKdsp33Id6rHtSJlWncg+d0ohP/rEhxRqhqjn1VtvChMQ1H3Dau0bwhr9kAMQ+959GG50jBbl9s08PqUU643QwmA==-----END CERTIFICATE-----";


	let Temp_p = crypto.createHash("sha256").update(pbkdf2.pbkdf2Sync(Password,URL+UserID,1000,512,'sha512')).digest();

	const S_b = randomBytes(32);

	if ((!secp256k1.privateKeyVerify(Temp_p)) || (!secp256k1.privateKeyVerify(S_b)))
	{
		console.log("invalid private key");
	
	}

	console.log("using credential protocol");
	console.log("=========================");

	let numLoops=1000;
	startT = new Date().getTime();
	console.log("start " + startT);
	for (i=0;i<numLoops;i++)
	{
		// client processing 

		let S_p = crypto.createHash("sha256").update(pbkdf2.pbkdf2Sync(Password,URL+UserID,1000,512,'sha512')).digest();

		var V_p = Buffer.from(secp256k1.publicKeyCreate(S_p)).toString("hex");
		var sig_p = Buffer.from(secp256k1.ecdsaSign(crypto.createHash("sha256").update(Challenge + Cert).digest(),S_p).signature).toString("hex");
		var V_b = Buffer.from(secp256k1.publicKeyCreate(S_b)).toString('hex');
		var sig_b = Buffer.from(secp256k1.ecdsaSign(crypto.createHash("sha256").update(sig_p+T).digest(),S_b).signature).toString('hex');

	
		if (i==0)
		{
			console.log("V_p " + V_p + " length: " + V_p.length);
			console.log("sig_p " + sig_p + " length: " + sig_p.length);
			console.log("V_b " + V_b + " length: " + V_b.length);
			console.log("sig_b " + sig_b + " length: " + sig_b.length);

			var size = V_p.length+sig_p.length+V_b.length+sig_b.length +T.toString().length;
			console.log("total transmission size = " + size);
		}
	
		// server processing 
		var S_date = new Date();
		var S_T = S_date.getTime();

		if (S_T - T > 10000000)
		{
			console.log("window too big");
		}
		isig_p = Uint8Array.from(Buffer.from(sig_p,'hex'));
		isig_b = Uint8Array.from(Buffer.from(sig_b,'hex'));
		iV_p = Uint8Array.from(Buffer.from(V_p,'hex'));
		iV_b = Uint8Array.from(Buffer.from(V_b,'hex'));

		if ((!secp256k1.ecdsaVerify(isig_p,crypto.createHash("sha256").update(Challenge + Cert).digest(),iV_p)) || (!secp256k1.ecdsaVerify(isig_b,crypto.createHash("sha256").update(sig_p+T).digest(),iV_b)))
		{
  			console.log("cred failed");
		}
		else
		{
			var P_p = pbkdf2.pbkdf2Sync(V_p,UserID,1000,512,'sha512').toString("hex");
			var P_b = pbkdf2.pbkdf2Sync(V_b,"",1000,512,'sha512').toString("hex");
			if (i==0)
			{
				console.log("P_p " + P_p + " length: " + P_p.length);
				console.log("P_b " + P_b + " length: " + P_b.length);

				size = P_p.length + P_b.length;		
				console.log("total storage size = " + size);
			}
		}
	}

	endT = new Date().getTime();
	console.log("end " + endT);
	var credTime = endT-startT;
	console.log("cred time = "+credTime+" for "+numLoops+" loops");
	console.log("Time taken for 1 loop = "+credTime/numLoops);

