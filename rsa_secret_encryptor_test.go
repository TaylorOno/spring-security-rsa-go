package rsa_textencryptor

import (
	"testing"
)

func TestSecretRoundTrip(t *testing.T) {
	enc, _ := NewRSASecretEncryptorBuilder().Build()
	encrypted, err := enc.Encrypt("test")
	if err != nil {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, err, "test")
	}
	got, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, err, "test")
	}
	if got != ("test") {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, got, "test")
	}
}

func TestSecretRoundTripCustomKey(t *testing.T) {
	exampleRSA4096Key := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
	key, _ := ParsePrivateKey([]byte(exampleRSA4096Key))
	enc, _ := NewRSASecretEncryptorBuilder().PrivateKey(key).Build()
	encrypted, err := enc.Encrypt("test")
	if err != nil {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, err, "test")
	}
	got, err := enc.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, err, "test")
	}
	if got != ("test") {
		t.Errorf("Decrypt(%v) = %v; want %v", encrypted, got, "test")
	}
}

func TestSecretDecryptWithoutPrivateKey(t *testing.T) {
	cipherText := "p+7ZIZjacsJZVQOiSusSGQBo0mF5yga7qOlfve0ugkXmtOQV2RnrzH2XuWraVeywXjhgWtrM6mqfBwjzwrU10VdZT21bEhBF5fWi6ZTP7IAbn5a8mlxBkjPhDSNxz4ycQ2xy4BMGtvSHVkLWHZP6ClIYh8ide4xlnRJ/QmC9GTrQIKVBrsIE+5AnfjQg1Ta/86UMZKzH0PPegPIm5u3dCbuLQ+DT5pdXjAWMuFkEFWB9W1ecfwEZ/2+VuiR5ejESAgbo7NmnHgKy4erXp5Swkrmft9XU69MOr7ky8IteYybrZ0hQ+b86HQDkuPk8Pjd+2wcx5HlkCtr4jm2vPbPsC2FhTYyJ9l+E01lwIESx2M1Rjl6b+KWihvdPZUVmq8chiFwSMwpRwf+XpLIEe7jZ4w2oI4tv9ATXW3FerVic03Mg8H6Rw97Sa80hZiqP5DEk8Bl7ecDgNzDqEoMwFd0CF6eM62o630yx4u6teZBdOCTqf1C30Wsz5AQ8nrN8MlFWJsF39SJ5ZeQnqYv3rEHP3n1yQNMAgZJSjn/QGqAB3FNNpoQDBwD/vsu0eY51mpAzmxID1UxVe3xsR1Hm0+5DWqtYlpFZznAlu+Tg2a8H4LmqX9UvG83G6RFDSSENTECUjnoN6fkIrOAs8IEpqG8B/KZFk6378b3klE0t6Yqbym8="
	rsa4096Key := "-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEAxaxK7dcGrvSJb1p9u16Ra6edt3UpuCwwcuZmGbhbYefSH7BY8/4t\naH43xF7Hrcf0RKWlsVDT+zmqstxuf2rihHWU0cL8r8Wh27+frG4R28eGt30PWraF\n+UnGPmmWEfON1q8afxNf4F/EIUui3a1+I+3gsoq+41jHBEupyQHebzynZxQJKLMs\ncLaI7U5mf/APqYulGCVB4e82gS1tItoOjHa65+0TOsNAUvyhhh1jsdgyrZ1kftVl\nzaMK9OE7d3Ls8Phtrxelavm9t4WoOvR8hSAVfk9fAlaUNKF8Ea9qfOddMqOFcC2H\nMYDe1IlfUs9mbedMcB7svuoQXYvbWl+TBnOf2TfDgFNEbOV1yybLD4v0CC4gb8pW\nQwzs+ADb2S6GxgC0ywEVtNUZmQ8z16tuL3I1Xl3/TaxXUzZILLOr9UE0ra9ekUMk\nFedEWD0zUvtbJlAHlRlhaEKkUDHcwbjXJyfOQqUQi9CQRdlwT19DfEWQdCl0HVnu\ne2chyQNVxoUKpRF8tqI03VLsHqjCvxWYVn27WOKb+p9g6i/wMzJQ48OS4gL7ySTE\npvxFS5Rz9s1o17uGaJ/eO6mnbkv5voRAqv8BCRtt6iqQutxRK/WhHUX2MCBfo4qT\nVFmbzYQ6ao3N13EbJ0jZmGkR4ZXwOzIRthQAih7SiUoohTsHUVkjfwkCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n"
	key, _ := ParsePublicKey([]byte(rsa4096Key))
	dec, _ := NewRSASecretEncryptorBuilder().PublicKey(key).Build()
	got, err := dec.Decrypt(cipherText)
	if err == nil {
		t.Errorf("Decrypt(%v) = %v; want %v", cipherText, got, "error")
	}
}

func TestSecretEncryptSpringCompatible(t *testing.T) {
	springCipherText := "AgA0wVsPHwrzwW0BISThbAlymmxjgUC32G3F0bU7WcJfGyDt/O94pm0Zo6eixropbQOGPKAPN91GHP7l9vNLqFdMXicROJFZNpD0lrNa9hKKSm1Ydq95zt5TZXUPCuSzASm8xE8sbyDco7ZU3OBjTbfiEv+Ef9dXq8ehLcFBxhcjYoAhqMXG10KbyQK0+v2DcFTwR/6hufH90SXLNYoOq1HMOMWnKEcAWD/HHNPOtJv9kRJXoLIxQpwqUVwypSJdghLQkjvVjLATtzAYgul1h7PayF4C7CF4w0QxFC29mQSMisVqGzagMSW1PzNuHiT/LuslV+wLChppHizyM4rHAIzVzRP1dVRCkJ/GKNvCve5u1b9kUgTZa86ZG8hxGdbVtBavOOMB7anoJpjKazatnaTgv3/hFYPZFml+N0RIXRmj7KzF8j8WLBMwCGevQjXCRZ9GUjvR7bVrezJqI5SskY35C8uRJ4Hs+zjwJFlOmPc1aXWPc53MWlTspeyzDK7+Qc1mnsLkw2j0LkmSGC33FNqIjqZiyBFP/prYWh3VSUwlevjTTHI8n9llhcKwx25f0mwR2wdt//4LkwBHyj6cfa9ZU9xuBsSYfNfqZ7LOXwp8qYZOA84uzj6Loyu25+W5eZoRinR4duczII+TYxxIC82CnuuH7MvxNlJIqotFSzLnX2TX61kcP3OV3XwkQomtcjkf3CXl3pxdwKv+s5NLXSaS"
	exampleRSA4096Key := "-----BEGIN RSA PRIVATE KEY-----\nMIIJKgIBAAKCAgEA0f6OsnpXJiLuTCtXs6gaPXGL/1kzHISd6Imo1Rwo6hDm+OA0\n95hW8K9wEjbWfkpJ1GZHqA45hvl7PVRvUimvdI6PsPeLsf/BeVIU039YsZB47zEY\nwfENflpHVJT+moa5QMAkoOgJVM5Bq6vI4CI/zv0LjqYQRmjOW0gtGSxIPcKOHjCB\nQ+d0TfHphLzd09YrwOgABeviGiPSqoNxcGV3a1tyvMxykqgK1LT+39njZKRXNVNC\nIeHy43Na9jw/O7jufigQd7lD3c+0IodX9GH6EVLnkn3IM+TQcA3GDSvMx6M/zANU\nvsJP0hfGhuzSMucxS+StcmshiaHmcv0XdnOEklOXGLoQ2w6ON3LjvxtqujkMMQMN\nOo2LjqdDC6EugZLYTqrJmXWemnIc+DBCwgvIvoKfpPsihpOVtE/UppvW5a6djbW8\nibd5pVjkdZEEs4bu+3ZFHFYPuaxXCCwqAvjvApBsYAoEURMGctNuDHpjF/oa/AXU\n3f5zoMhXRdTgH5Kxkb2utxETcqgqu6Z6qsjRZBDNWrof9gcuSbvjYFe4cX/N5WNx\nc6Z1cYOU7tHAx9hWo/WJWkR36fQpv1fwG54zQirJgOnGIx3/81uKziWzpbBNioEM\n1XKW0lnuIf2/mn903j7s0C7PRsdJNQIx+oBCqcrC4e3W+cM0/2qaSGSpLGECAwEA\nAQKCAgEAg3p3S8YPlKAgRW6JvcGNlFToi5sExmE+IR83px63ez3T75UpdLBcFtwx\nNiZBi9blfOgBC3bEi/7eK5sXDAFvinHMA8gqHet87oH26ij8lkhXf6Nk1eEgSrEp\nogqbkpKxoJntFRXS6dcuBNdMsRCglO+YcdsFq5/pO/vnyLASFyEeLEbAWIytJDRH\nukUqOn0I7gIUKaDz8tvlBb/AodfVulEKeK0lOy+dgGpGfk+E8Tl4JLoZWO+ITOKn\n3C4ChVkXccOR8/P6SwHFziyhZDCICpq2xOCeHeewncfx7cMztvc+dXTMdZdhtLAQ\nK+BRB2/7TIJEGrR6zhqhF/Pg4dgX8waL2pWeD8n/Pl8eplvoyxb+M1XVy26FCRls\nfUN2f195X0ZHcFm/FgKzZw7Jspo8ZwpzTr9kXMd4aM/iIG3chvvk7XJW0yQtGP2J\nxl2q4caVFLY2oySlwImub3UMMB7xdkEXudo5ITTawd6sSNNFTm4e6rwmHa/kACSA\nu0vPbEec+7HXdATOhIz8h2HJZhO0vnHvsKU3fR33qy4dPVYHpQ9j4p53p9BHH6px\nGh/6xkCd6NquzAv0AEIew8ClbNfEY7ylQyFGhWhRx1qaSl5zjLrhDhvraOkEnshO\n060oHF0MkFkUjoUBXyuDu12nmj9Wq9kKKwW1yk0EVabXsF/WBLUCggEBAP1G5ra9\nDomm2iYkQMKKnbnmzOXIpmkGk6g3J6F9NYaspKwdseTqTBhF8o3mRZBx+Wfad+ZL\nzgn47zs5P1IUqPbVVlxZleNjh7tvBEtCa78xrhY+nvfPYx0NQjZkZaX1XDzEQKXH\nlSeiRExFDXRJAmOMVBwIvQ2cgsw85XQ41WCpbo3cPLSIep4DvF1vE81PC9SkQ4as\n8NO6MUblNXaPn79ywKTHW/Xz38Bwi+cbjswdTB37DiOLib/X492OanSY9JOkNp38\nRPs6l/0EIOPVbEWT3E+mcmt2Kbgo8vxOHjW0hhqgHvqUbF32S+ZwFGVnrgxnU0Hq\n8nZ64UvI0LIyqBsCggEBANRAh1oJmoU4xF69pmwYsq4qrGEKP+2jrADAkhBaFBqK\nUM/rSzyIaSq/DCit/qs/TcSnHBUTPKczxIkv6W5mY6u8QQ+6hk4OFdAAW6VRfCJP\naKS2l6aasdaMgOSC24MxHk2hTcpZX8PcrMtDRwkoerLxJmf6y+k5fdko66nWWWFy\nFY5SU3RHR/NJTXGuM2jFlIReVGFJF8vW6Ykl5m5boNNsIcd0CxmOilWgUxAl35Rq\n8g6luEZhm/p0OM2LduveGQ11tfaa5BOEBOb3ZRM21xh/ilaZYm628sgN8QjxmpoQ\nnhT1caa5/Oz1aMJ/eV4pNI5/xHOUbz81qxSfLLI9/TMCggEBANb5eRYd/drkXkEF\ngFofYaTKu5tF5ck7JdUfi2nMZsQ6gUL9qWLNY20u4aODkgP6WWDG1AIK0YUxX4z7\nGD3I/2kSxsx31Xs9nZV/sztV0zJjLon++NsJkey0tkCIkqZ8TZ/eS6jqcDVFy4aZ\nDcRnu7lXAIUS/bQx5esIvREatDHpXcbW6kepl7nLHfSINVyL/VStYAtNetObM/wi\nzHAnk8Xh1pWGCQ4HwyEJ5hVxFJE3RMYls2iEJZVJ30TMfpscwGsYdKs/1iUPJLZC\n7M+09MNRryuD8ZY4o0yGpUd13rpi0XiD9AdoN1rBlMaw1v8DM32frdFDZC0gO14h\nwtGdoYUCggEADnKaBAH1V64mh8BnDKKdvwc+lphpA5cJhT+WcbB//9J8b7q3c1Zh\nujwo6rf1RtjXRVSOr8yQa101upTdUdt8W1tEHnr222dQCsmLc3RZe8hl+hhHuFp9\nUnpb57IUmRiF1IjvT5/HygBCbs+UjUYJHBcYIynKKYT1UQvdBsGFcgGfAAIQljCn\n8CKEOAHAlBgm5N+65KhiC0kEuoYu6kIob1vD7Ny0SLgQKIXyQX4ieurQsTiMk5Xf\nVSwGFc+xd5q1n9nsWe3vKnjpEIO0iJtKBuvfkcd9EMY5Pm7cglxXxrbs28ZdRxkP\n411NFTgyHbu2TSDbUXbAH9BaZdvz4eogSwKCAQEA17K8N2iJ4DlAnvo6/GgpiN5D\nsjSrIL7Y9zhpcdTrR5LVLqVUzzh713BUjrb4lM3lUZi2AzhSHisrcQqiSTJzzPSq\nA7lCgUGnlGWVmgxpWIIliCKEM8n5ZFZW8qjyI3QDQiTM6ECXdqsGILhvPmBd3Lo6\nlM8CPnatpLd1Mj5xQ+0y9jvLis5OC8yCR4i/PXbLrDOkhrKn4kXKbO9uUJppTN7S\nGgqBkuq2Mo42Zruab0Eex8xqxAQvCPwUkZOPM3kXnnHUMsAZ7UkbDmRFT7FxeIxs\nXuTolyjDSCxCxqCmnHa674Dc0Sc0Sx7WJVlUTBBwQ5YLewDgMwr+fKYQSxI7Ug==\n-----END RSA PRIVATE KEY-----\n"
	key, err := ParsePrivateKey([]byte(exampleRSA4096Key))
	if err != nil {
		t.Errorf("Failed to parse key")
		return
	}
	dec, _ := NewRSASecretEncryptorBuilder().PrivateKey(key).Build()
	got, err := dec.Decrypt(springCipherText)
	if err != nil {
		t.Errorf("Decrypt(%v) = %v; want %v", springCipherText, err, "encryptor")
		return
	}
	if got != ("encryptor") {
		t.Errorf("Decrypt(%v) = %v; want %v", springCipherText, got, "encryptor")

		return
	}
}
