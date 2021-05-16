package rsa_textencryptor

import (
	"testing"
)

func TestParsePrivateKey(t *testing.T) {
	exampleRSA1024Key := "-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQDUAPQjb0yMyD/5amQjHWRfVmpQHTJMENkI2CONpHjEe/fA/0PY\nsCacjforWgcwuGg91syra0zSCEVql+PlfioWLYcxm9SG+9FWJwK4cSdLEnZWEnzi\nDSCuTnczUvJPTT7fJ/wKagQGXBoYnWZX9uZA7aIOlFcnvXYq7ysRlj9nyQIDAQAB\nAoGBAKYnFTAMU59mdhUg19hZecfqbynYqAnLjn2K/9pL08aSLetZZDAYZjp+X1nI\nligN7szAYunaD3vwtY7D+f1rssj/lrvkUkzkiuNro7K/yDTg+wGEQOJrutRtWbfE\nXIU1qisyhQ8m3aldySJtq5Xcu6bJiNPxV7JK5WdBbFTFLnYxAkEA77O3DM+bv7wm\nbXjNU7/Ujhc4k5OrwMKvKUzVTmb8xZMPN7Sv7Xbv1Mim4bdZmVDfc+X9dY3mu5Vd\nH2wS4ZjybQJBAOJrHltfZ51QdoB1uctir1NF/2kEx+02vu8G8cbmJ8Up2ghzUzrh\nkWFXbyMrRnlyfoWp4J0kBE15V7LKUqpyUU0CQBuv9IrkSCdDgmTOuVjdJZ4sDHrv\nab1gP39TwqfFuZjQvcc/dbrGLDm126Di3tSYxNbMUBSOCYLNY+5HO38XfZkCQEPX\nnuf4BT7w3iENpVcYwbns7mPUR+d/EOTkKsvTKLV+HdOMYrLw5bPKFAXwsJQxR1Hb\nne7X3OYt5qYu02g5Cr0CQDfFVHEn9EmvBUIORGvFi6AZebWBkPT2tZM4NkI55P/W\npKr/gDrTR5I1qv7qNl6GE2WR2J4I3VuMXOZI05sw1EA=\n-----END RSA PRIVATE KEY-----"
	exampleRSA2048Key := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAzUFcswe9J8kBB1PHWTu5uhv+AoyBYpXyoU23eyfrhYg4g/ET\nvgww4//+sS1nHBuVzRxBqs/hiYz3jGW41yh3qex3hJ8gflsRCTuigUWsJEwOtk7x\nBLAGa3wCxFm77yO9o7lcEbabPFigkWx7KobRbK5WPN2N0HGnxZkLm++OrGOgDrps\nivr7UFsvPxA1D67tu207R81b72e5rcNQ8rOcAyp4xEWqLGEYlpAsyqJuf3OnErmQ\ngUNfTxwFEWKu7NaMrU0giLABcw779nQz5gyM364BTewgB99SVmSiChUoBDuNyBYn\nVxIGNOJZIUru1m9ggqVVc36ykqS+/q3/Z6ZD1wIDAQABAoIBAQDCF93l+hp4Bc5w\nNFwdWKofgJrppB4xsKP4vroTvsMryY3PzuehXnvZDtm0h7+qR7eXdvHt6ZhX7zKj\n1Ak/hKfryo2WnrcmZU0t0vOvlMfcpwN+iBXIHgBkIaeoL0bVM5H/wad7pJcVMKXd\n/pxVsZlWUWGBOu0AwIkrBLeCpLzg677FYfh4/ebgwrj3J2EdF6Di9KHIvsYEXJhY\nL7CsbrhGhanPQT8LhEyCabugNHwuL0SZqn0XHv3zVw6B3t3Jdyskm5j5o/4wFr5H\nvCzDQK028+EBfs0ZWNwwKE8jR5dTLc3xVESL8UBBskz2wLnqhVrM6I6DBH1jagMM\nw9TVHCG5AoGBAO02uL049a2aU0uUYGuq6vsYYZxUdEmHFaWyHOmNJJq3OZXtM2zS\nzvk3/3TlJNDZQ2/Vck7f29y/r9P6dKFnTv1hnGumdLDo7nUKbMInJ0RmE1wTVSpC\nYsunffU696Vc0UL7L3Of98J2C7UMAhZlqCppEpdNcQh0BeeZs/IxgBSzAoGBAN2C\nttjgcBYJgALJ99Ccw5e3Av4flSwfEfgBe4wOrWajJ8u9qHwo/8JB7N1YyS30/YgH\nyr7w3EvrnU7XEeB2DB+139UzzaiEhZUI+d9bA7NbkHV+3Wef8hMwcR9svqn6/Vlq\nK1g0Pio0aoavDUjNYL2YHZlS9Jv/J37hQeeqqM5NAoGAEqMS/qLkAoC2fKCqtqrW\nDWZL/PlRrZk0ZTFKPjs9nf45QwNA4BLr+f6hTnDWZKY9OyMc+P9zibNxwAjUcv3n\n4dZycK7CSkfyvDVWeCaVWjVe3gQS0+AlXPTK26KHZHGXa1jK0J3H3HpjzxSjcVkJ\nTlO1BzgpYk2jTR/xWFz1QCsCgYEAmKNCLCA8HHNfaoyR34amoRzTSxmoSUb/ss4S\nvGhAxMEY4yRFvYji9JFJDx3nQ2vWaK41321J4GbzdyhsgSfXIuLI4rlXtg/bnN8a\nj/a/jhBCczSAjK+CuAZhbS4aFDeH7N1kENuvGpYT8csedFRRnVP80XKAbB5esOe3\n6lOHDuECgYB9N825irbGqz2hl0Sm2gi9c3WXyjQoNdEsaE8I2+PVUtbFvQXtS64O\nz95BQEZlXB7OuIaUeKiAohwXLSMBOAboPSFhFGwLmxG4Z0tLys/9X0g6C88lK+ax\nCzmpWVJIcLWVMFRdkBmDWBw/5+Npwj5iyocipXx0bHw5DTnUePfiaQ==\n-----END RSA PRIVATE KEY-----\n"
	exampleRSA4096Key := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
	exampleRSA4096BadKey := "-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n"
	exampleRSA4096WrongKeyType := "-----BEGIN OPENSSL PRIVATE KEY-----\nMIIJKgIBAAKCAgEA0f6OsnpXJiLuTCtXs6gaPXGL/1kzHISd6Imo1Rwo6hDm+OA0\n95hW8K9wEjbWfkpJ1GZHqA45hvl7PVRvUimvdI6PsPeLsf/BeVIU039YsZB47zEY\nwfENflpHVJT+moa5QMAkoOgJVM5Bq6vI4CI/zv0LjqYQRmjOW0gtGSxIPcKOHjCB\nQ+d0TfHphLzd09YrwOgABeviGiPSqoNxcGV3a1tyvMxykqgK1LT+39njZKRXNVNC\nIeHy43Na9jw/O7jufigQd7lD3c+0IodX9GH6EVLnkn3IM+TQcA3GDSvMx6M/zANU\nvsJP0hfGhuzSMucxS+StcmshiaHmcv0XdnOEklOXGLoQ2w6ON3LjvxtqujkMMQMN\nOo2LjqdDC6EugZLYTqrJmXWemnIc+DBCwgvIvoKfpPsihpOVtE/UppvW5a6djbW8\nibd5pVjkdZEEs4bu+3ZFHFYPuaxXCCwqAvjvApBsYAoEURMGctNuDHpjF/oa/AXU\n3f5zoMhXRdTgH5Kxkb2utxETcqgqu6Z6qsjRZBDNWrof9gcuSbvjYFe4cX/N5WNx\nc6Z1cYOU7tHAx9hWo/WJWkR36fQpv1fwG54zQirJgOnGIx3/81uKziWzpbBNioEM\n1XKW0lnuIf2/mn903j7s0C7PRsdJNQIx+oBCqcrC4e3W+cM0/2qaSGSpLGECAwEA\nAQKCAgEAg3p3S8YPlKAgRW6JvcGNlFToi5sExmE+IR83px63ez3T75UpdLBcFtwx\nNiZBi9blfOgBC3bEi/7eK5sXDAFvinHMA8gqHet87oH26ij8lkhXf6Nk1eEgSrEp\nogqbkpKxoJntFRXS6dcuBNdMsRCglO+YcdsFq5/pO/vnyLASFyEeLEbAWIytJDRH\nukUqOn0I7gIUKaDz8tvlBb/AodfVulEKeK0lOy+dgGpGfk+E8Tl4JLoZWO+ITOKn\n3C4ChVkXccOR8/P6SwHFziyhZDCICpq2xOCeHeewncfx7cMztvc+dXTMdZdhtLAQ\nK+BRB2/7TIJEGrR6zhqhF/Pg4dgX8waL2pWeD8n/Pl8eplvoyxb+M1XVy26FCRls\nfUN2f195X0ZHcFm/FgKzZw7Jspo8ZwpzTr9kXMd4aM/iIG3chvvk7XJW0yQtGP2J\nxl2q4caVFLY2oySlwImub3UMMB7xdkEXudo5ITTawd6sSNNFTm4e6rwmHa/kACSA\nu0vPbEec+7HXdATOhIz8h2HJZhO0vnHvsKU3fR33qy4dPVYHpQ9j4p53p9BHH6px\nGh/6xkCd6NquzAv0AEIew8ClbNfEY7ylQyFGhWhRx1qaSl5zjLrhDhvraOkEnshO\n060oHF0MkFkUjoUBXyuDu12nmj9Wq9kKKwW1yk0EVabXsF/WBLUCggEBAP1G5ra9\nDomm2iYkQMKKnbnmzOXIpmkGk6g3J6F9NYaspKwdseTqTBhF8o3mRZBx+Wfad+ZL\nzgn47zs5P1IUqPbVVlxZleNjh7tvBEtCa78xrhY+nvfPYx0NQjZkZaX1XDzEQKXH\nlSeiRExFDXRJAmOMVBwIvQ2cgsw85XQ41WCpbo3cPLSIep4DvF1vE81PC9SkQ4as\n8NO6MUblNXaPn79ywKTHW/Xz38Bwi+cbjswdTB37DiOLib/X492OanSY9JOkNp38\nRPs6l/0EIOPVbEWT3E+mcmt2Kbgo8vxOHjW0hhqgHvqUbF32S+ZwFGVnrgxnU0Hq\n8nZ64UvI0LIyqBsCggEBANRAh1oJmoU4xF69pmwYsq4qrGEKP+2jrADAkhBaFBqK\nUM/rSzyIaSq/DCit/qs/TcSnHBUTPKczxIkv6W5mY6u8QQ+6hk4OFdAAW6VRfCJP\naKS2l6aasdaMgOSC24MxHk2hTcpZX8PcrMtDRwkoerLxJmf6y+k5fdko66nWWWFy\nFY5SU3RHR/NJTXGuM2jFlIReVGFJF8vW6Ykl5m5boNNsIcd0CxmOilWgUxAl35Rq\n8g6luEZhm/p0OM2LduveGQ11tfaa5BOEBOb3ZRM21xh/ilaZYm628sgN8QjxmpoQ\nnhT1caa5/Oz1aMJ/eV4pNI5/xHOUbz81qxSfLLI9/TMCggEBANb5eRYd/drkXkEF\ngFofYaTKu5tF5ck7JdUfi2nMZsQ6gUL9qWLNY20u4aODkgP6WWDG1AIK0YUxX4z7\nGD3I/2kSxsx31Xs9nZV/sztV0zJjLon++NsJkey0tkCIkqZ8TZ/eS6jqcDVFy4aZ\nDcRnu7lXAIUS/bQx5esIvREatDHpXcbW6kepl7nLHfSINVyL/VStYAtNetObM/wi\nzHAnk8Xh1pWGCQ4HwyEJ5hVxFJE3RMYls2iEJZVJ30TMfpscwGsYdKs/1iUPJLZC\n7M+09MNRryuD8ZY4o0yGpUd13rpi0XiD9AdoN1rBlMaw1v8DM32frdFDZC0gO14h\nwtGdoYUCggEADnKaBAH1V64mh8BnDKKdvwc+lphpA5cJhT+WcbB//9J8b7q3c1Zh\nujwo6rf1RtjXRVSOr8yQa101upTdUdt8W1tEHnr222dQCsmLc3RZe8hl+hhHuFp9\nUnpb57IUmRiF1IjvT5/HygBCbs+UjUYJHBcYIynKKYT1UQvdBsGFcgGfAAIQljCn\n8CKEOAHAlBgm5N+65KhiC0kEuoYu6kIob1vD7Ny0SLgQKIXyQX4ieurQsTiMk5Xf\nVSwGFc+xd5q1n9nsWe3vKnjpEIO0iJtKBuvfkcd9EMY5Pm7cglxXxrbs28ZdRxkP\n411NFTgyHbu2TSDbUXbAH9BaZdvz4eogSwKCAQEA17K8N2iJ4DlAnvo6/GgpiN5D\nsjSrIL7Y9zhpcdTrR5LVLqVUzzh713BUjrb4lM3lUZi2AzhSHisrcQqiSTJzzPSq\nA7lCgUGnlGWVmgxpWIIliCKEM8n5ZFZW8qjyI3QDQiTM6ECXdqsGILhvPmBd3Lo6\nlM8CPnatpLd1Mj5xQ+0y9jvLis5OC8yCR4i/PXbLrDOkhrKn4kXKbO9uUJppTN7S\nGgqBkuq2Mo42Zruab0Eex8xqxAQvCPwUkZOPM3kXnnHUMsAZ7UkbDmRFT7FxeIxs\nXuTolyjDSCxCxqCmnHa674Dc0Sc0Sx7WJVlUTBBwQ5YLewDgMwr+fKYQSxI7Ug==\n-----END RSA PRIVATE KEY-----\n"

	tests := []struct {
		name    string
		args    []byte
		wantErr bool
	}{
		{name: "1024", args: []byte(exampleRSA1024Key), wantErr: false},
		{name: "2048", args: []byte(exampleRSA2048Key), wantErr: false},
		{name: "4096", args: []byte(exampleRSA4096Key), wantErr: false},
		{name: "4096 Bad Key", args: []byte(exampleRSA4096BadKey), wantErr: true},
		{name: "4096 OpenSSL Key", args: []byte(exampleRSA4096WrongKeyType), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePrivateKey(tt.args)
			if (err != nil) && tt.wantErr {
				return
			}

			if got == nil {
				t.Errorf("ParsePrivateKey() got = %v", got)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	exampleRSA1024Key := "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBANQA9CNvTIzIP/lqZCMdZF9WalAdMkwQ2QjYI42keMR798D/Q9iwJpyN\n+itaBzC4aD3WzKtrTNIIRWqX4+V+KhYthzGb1Ib70VYnArhxJ0sSdlYSfOINIK5O\ndzNS8k9NPt8n/ApqBAZcGhidZlf25kDtog6UVye9dirvKxGWP2fJAgMBAAE=\n-----END RSA PUBLIC KEY-----"
	exampleRSA2048Key := "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEAzUFcswe9J8kBB1PHWTu5uhv+AoyBYpXyoU23eyfrhYg4g/ETvgww\n4//+sS1nHBuVzRxBqs/hiYz3jGW41yh3qex3hJ8gflsRCTuigUWsJEwOtk7xBLAG\na3wCxFm77yO9o7lcEbabPFigkWx7KobRbK5WPN2N0HGnxZkLm++OrGOgDrpsivr7\nUFsvPxA1D67tu207R81b72e5rcNQ8rOcAyp4xEWqLGEYlpAsyqJuf3OnErmQgUNf\nTxwFEWKu7NaMrU0giLABcw779nQz5gyM364BTewgB99SVmSiChUoBDuNyBYnVxIG\nNOJZIUru1m9ggqVVc36ykqS+/q3/Z6ZD1wIDAQAB\n-----END RSA PUBLIC KEY-----\n"
	exampleRSA4096Key := "-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEAxaxK7dcGrvSJb1p9u16Ra6edt3UpuCwwcuZmGbhbYefSH7BY8/4t\naH43xF7Hrcf0RKWlsVDT+zmqstxuf2rihHWU0cL8r8Wh27+frG4R28eGt30PWraF\n+UnGPmmWEfON1q8afxNf4F/EIUui3a1+I+3gsoq+41jHBEupyQHebzynZxQJKLMs\ncLaI7U5mf/APqYulGCVB4e82gS1tItoOjHa65+0TOsNAUvyhhh1jsdgyrZ1kftVl\nzaMK9OE7d3Ls8Phtrxelavm9t4WoOvR8hSAVfk9fAlaUNKF8Ea9qfOddMqOFcC2H\nMYDe1IlfUs9mbedMcB7svuoQXYvbWl+TBnOf2TfDgFNEbOV1yybLD4v0CC4gb8pW\nQwzs+ADb2S6GxgC0ywEVtNUZmQ8z16tuL3I1Xl3/TaxXUzZILLOr9UE0ra9ekUMk\nFedEWD0zUvtbJlAHlRlhaEKkUDHcwbjXJyfOQqUQi9CQRdlwT19DfEWQdCl0HVnu\ne2chyQNVxoUKpRF8tqI03VLsHqjCvxWYVn27WOKb+p9g6i/wMzJQ48OS4gL7ySTE\npvxFS5Rz9s1o17uGaJ/eO6mnbkv5voRAqv8BCRtt6iqQutxRK/WhHUX2MCBfo4qT\nVFmbzYQ6ao3N13EbJ0jZmGkR4ZXwOzIRthQAih7SiUoohTsHUVkjfwkCAwEAAQ==\n-----END RSA PUBLIC KEY-----\n"
	exampleRSA1024BadKey := "-----BEGIN RSA PUBLIC KEY-----MR798D/Q9iwJpyN\n+itaBzC4aD3WzKtrTNIIRWqX4+V+KhYthzGb1Ib70VYnArhxJ0sSdlYSfOINIK5O\ndzNS8k9NPt8n/ApqBAZcGhidZlf25kDtog6UVye9dirvKxGWP2fJAgMBAAE=\n-----END RSA PUBLIC KEY-----"
	exampleRSA4096WrongKeyType := "-----BEGIN OPENSSL PUBLIC KEY-----\nMIGJAoGBANQA9CNvTIzIP/lqZCMdZF9WalAdMkwQ2QjYI42keMR798D/Q9iwJpyN\n+itaBzC4aD3WzKtrTNIIRWqX4+V+KhYthzGb1Ib70VYnArhxJ0sSdlYSfOINIK5O\ndzNS8k9NPt8n/ApqBAZcGhidZlf25kDtog6UVye9dirvKxGWP2fJAgMBAAE=\n-----END RSA PUBLIC KEY-----"
	tests := []struct {
		name    string
		args    []byte
		wantErr bool
	}{
		{name: "1024", args: []byte(exampleRSA1024Key), wantErr: false},
		{name: "2048", args: []byte(exampleRSA2048Key), wantErr: false},
		{name: "4096", args: []byte(exampleRSA4096Key), wantErr: false},
		{name: "4096 Bad Key", args: []byte(exampleRSA1024BadKey), wantErr: true},
		{name: "4096 OpenSSL Key", args: []byte(exampleRSA4096WrongKeyType), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePublicKey(tt.args)
			if (err != nil) && tt.wantErr {
				return
			}

			if got == nil {
				t.Errorf("ParsePrivateKey() got = %v", got)
			}
		})
	}
}
