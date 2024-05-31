package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/theQRL/qrlft/hash"
	"github.com/theQRL/qrlft/sign"
	"github.com/theQRL/qrlft/verify"
	"github.com/urfave/cli/v2"
)

func generateRandomSalt(saltSize int) []byte {
	var salt = make([]byte, saltSize)
	_, err := rand.Read(salt[:])
	if err != nil {
		panic(err)
	}
	return salt
}

func output(filename string, hash string, quiet bool) {
	if !quiet {
		fmt.Printf("%s %s\n", hash, filename)
		return
	}
	fmt.Printf("%s\n", hash)
}

func main() {
	app := &cli.App{
		Name:  "qrlft",
		Usage: "QRL File Tools - See docs at https://github.com/theQRL/qrlft",
		Commands: []*cli.Command{
			{
				Name:  "verify",
				Usage: "verify a dilithium signature matches the target file [eg. qrlft verify --signature=3b4e... doc.txt]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "sigfile",
						Aliases: []string{"sf"},
						Usage:   "Signature is a file [eg. qrlft verify --sigfile=signature.sig doc.txt]",
					},
					&cli.StringFlag{
						Name:    "signature",
						Aliases: []string{"s"},
						Usage:   "Signature is included on the command line [eg. qrlft verify --signature=3b4e... doc.txt]",
					},
					&cli.StringFlag{
						Name:    "publickey",
						Aliases: []string{"pk"},
						Usage:   "Specify the public key of the signer on command line [eg. qrlft verify --publickey=3b4e... doc.txt]",
					},
					&cli.StringFlag{
						Name:    "pkfile",
						Aliases: []string{"pkf"},
						Usage:   "Specify the public key of the signer in a file [eg. qrlft verify --pkfile=publickey.pub doc.txt]",
					},
				},
				Action: func(ctx *cli.Context) error {

					if ctx.String("signature") == "" && ctx.String("sigfile") == "" {
						return cli.Exit("No signature provided", 78)
					}
					if ctx.String("publickey") == "" && ctx.String("pkfile") == "" {
						return cli.Exit("No public key provided", 78)
					}
					files := ctx.Args().Slice()
					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					for _, file := range files {
						file := file

						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when verifying "+file, 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when verifying "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						signature := ctx.String("signature")
						// signature := "6ca71cbdf6768668d04a5bb784ed4af4fd298dc3ba3802bdf2e724cb0e28f65deb98466825a940acc363efd51e9f66c985b813ec1d1729181fd4978dc70558aac75ddd9184a47d9bbfda8bc7903559be36bdb5cd7ad2ee04da8835940e185bdcc4e81e75f891dfde9011d03f08f74b54a1bcbac994aebbfa161215cca3c9b922a237f31bb34120eabd7724b61673272d1f78ec1f619b9c6a1e909f1a85f723ca7f729fafcf8c04bf20a3bccd2a39af23f8e85aa7a97ccb7d7dab1f706c370e1297a6784be44ab8446402cbcf7a7d0b477be340037cac540369e1a55e7816a049ac8f694dc2b18db8f649f28f09fb5318a218d8b5ef385b9107b7a79304f2592e197b501853c76e595e68d4a660e743d2c2f0f8b9ca1554b7bb6b57792a2ffff103c445ae0754fc08021f007708777d00ea264de1ac9044bc555232281f8d6e7fe88dcf6e6b21c6d52927fdd8f910d9076461c8e0aabd0015282750afe87695e2efe1b36db32e5ab9858c03264e4034f8b295d94a72cc363856d47476df6f117042a0cd6c177958576b2103652ed4af6df865d70620c430596112b9b5d9f874629c8551478f69414bbafb682e8c7a54e6e0a9978bc1fd8701a597ee6a404cf6b07c8ddc8854df5e29890929e0fcceed3bf73b1c8a1ec0895ffb147d9941b094d1dbeeead031279b66008b658e96151b242ecaf429740e42e7c768627bcc7d4ad6410f3e9e6255bb70787008c2c20e597929d420e049bd02d07b321596e141600c0b0ad347b4c3e4c48f2dfa9f205d12ada831e207cc39f14e214f3e99cdf93c372e8352480cead76f226040ee4171afdc340ac1828c3f1ba149f7e43c8fcb0fe9c69c2f624cbd9118b46481512f4098dab7f7869db5998304737d8348c1b1abd9f5ef5258c6341903a5a3b5c341405cf13dcc202a5eaf6d25f52c254b4f7bc0150d5589f83c408d87cdcfbb0fc48eec8fb1492335135233f02c1f247b4b2f3ed6d581b85c2ce5bb61bcd935d0a546f4c10fa14b941fa343fe6669cf051b6aa163de80b2c44965c6a2f8d4e391bf5b476c3a1f2e837a9a7fd9c603b83a41abf72d872d47db6e71a2387d20cd1b0dc7d798ea09872eaeab6dbc9213bf7341ac3d2a1f0141f87b1b957965a3a86ad83b6b889ad272a6bafb7556c9a84ca36d8c18b3c8581ebe612e7c3d9d46d90b16813595fc123b89d88c6bf62c3a4259078d31ab5a8fae0ce8399da4332d295f761062e5022e88b719d38310941e3e8069c7e6ce601fa509b927166988f6b5e6554852737e5f5f88d6fe90d9b20387e1a6f47d2a54d27399fb16469f4fd363f7948682285de07ac6c9610eee263e406d9e0caf577b39ffa75e9e643954bdd01dd6d15714fcbb414b0e63063798a93dd73c9b4de3011300620674467137a17718ac2f80aa1e0bfa3634b3f1d3898cb7f649e1e63b93c7c69400525eed3674115d8f66dcd3f9f2004a06688a07763cd6d16dd4e8a3711d4e97eb075a4ba4d884202b43ed29a10cbd69f311b65699a5ef01bcba241ff4980062b4dcbf9f67cef7f24f792b0a0155681c73efd72b3742ec0fcc7c8e93b21a3e4b9b6566bc1a9611e1b2b0bc344c967f373806bb8a19fa3c935c1c8745010af94057f082cc3a7a892b6028e1ebfc1ff626ac82ca51f105c806da9803fa9d0d69707239cdd8d618405358f26193b45aa085bc1e7c61fecaf5ca7de7e6a54add4a676ed4195e1982d7138edaf1a065253266fca59f3c2511fcd42beb20d80265e655afab22a6a0f2be05e344b6dec29075c68bd3f994e1261c27ce23f885681b396a569d8f9ed0b6127b40e8a4b5101a2bd3c2ba4f5d730d18cd3b16b48fde3e5d067655c88434957f49b1361069b6ea5859a93fd0e7a363c72559a24ac7c576dc6a9d8bf235aced567209853f405405f0f7063965bdf6333c93557cd3c7f9ec8747a71a6e366d27347f481c6fd1c64798b4a4429f2369451968f18598f91705e948028fef3ac79fd6d27c31b6d9b63c05582657887047f2386a4641b83dbf58b572bbd67c4365722663f1fcd7edd95160be6a9e3a0c278dca164deca5696fb8d65e2ff1cb48368ffe784974c13db0d58393ab1a1f79847043265ea99814aaa1a804ab41b928d6af4ef37727e8b7843e0a57f0ac2f25b40135ab838d35b49dd6cab7132050cb39ac86a579cefb8ed400ae9810c80d3ea947ad939f5c4539a5f9a52409db72a71a0399643d197112d455f5cca3bd0bafd75ace1fbb0967c7dd8f4b8f6a19dd90c495bbb6583fac78da9c9b86dc8cc2f3012e41e516c7207cf6cfb2dcbd35452ba97f4c29a9c0439a3b12fdaed7f141dad1b6a121e4d30df268e2e5730d0ca0b363a154b85e1cce6a9f457d3a089c7b47152c351926029435d958abf9e22f3c364f09a414865ed68cc11bb8969adf0258fb0312a4af4c4a1200c964d75a4184c00e9d29a9d2795a82ee729812aa4bc3b40d247818e0d0e94b274a11071e6d4ffbe110ed1ac0fcf2be347291cdcde8fa0d0db8a08e9da24ac8536d58ee0bb7079b471a8b43a58d2930704a35592d9ca3ed5b5ac20cbdb34df81095694538fbbdea52d6917aba6c2782675a589606b3fb97a74c2e34d438eb66cfbd884c0ec67e934f6c5b178b938cd1875eab485a45ebf09ea4fa11a55f2f050db27391733fed1e7830a8d8a5a6611db057a3214fbc8f0de8ad8ba48a59f8508387550accbf18602e6c30bfff134b728961b07d9180e8f41dec133bc47c7fcf4904daceeb4d87343d839bffa276059265cd910ac6c8aac6f2234704a68a2b7ee4f02fb343f2a66e4c5f2a6ea85a05c4254b2cde8f2e41647b513121e0f4c8fa50156942b0636e6b9837807e0642223c6e106978571682c946ddbc90b2c63c9dba44c944d3c1fa26b706f7551595ba59ac4baf6246df89d761e2ee590eb56dada666a0c35e1482ff0e78eb88df449b4610fc3db67bd9de3b9cffb9f394afa45dfadff9d77c9ff03d50a1f5308e956362dac4d7bf69c45e9899b52eca8ff7edeb6d47ce23a18fe5c3c5764cde74d703121268b4e0f727c034b0183d47b608039aaa9cf1b14b9fb9d7064339bb05446c28352853e2833d6a76be7b344b71fc7aa5a0be897579099778f534b30aee6661f487ef8bee32ebee12e670ea4d9844169d62db9b577ff19e6d49a664d3907121c28a8ef12d5478e298089b0fa66bd1c17cd4fb971fd2ba293a0a15cf3d8239e6543e61c31603e9a47d0fc5bff79361b435eac341943f2d9c22bb757687e0e9cc94357fc267b0a83592210fc51a1f57569a4b2d2bcd250a950512d92981b45cbbc1b12ec658c8eea658f6013df40c06fc12178023aa7014421f332a5cc0ea1810de2267796e138aed835b66b752e5b4ff8a1bfc6fa34948d4f1715e40464ede1560b817495c999e6cc76dc514bc6614dfe64335074c21beb0894d5bee7ce508bc7b18ebbdaba8cdd164dcd7ee2e3c7bfa3d586865c55746ac46376cec01e9865f689327dc1ef2c87e7200592d523a80b0779009e250abdfbd7e390ee893c842a4246abe9605a0f3c3e3f1e2b8e544b5649f68fc53bd17b48b227d9a96d6dced3a85e7e0b949f9c66050c324845988103ff6d4047c36728b032154665518b585e1d518a6577e073d753155dad4515c51b64aa9eb194ef5fb749f06960c2a8a6fe6d1957fe09b0ddb3756d971800d12144237426548dca96bd707804bc1764e1d7cecba726853eff8741e9c5f855e1516fc2c382e8c3676389c0e191fd7fdf16f9134520d72060473301d687bd6833c7908dd42c09fb273678030771fb8f8294f7f7f5cd37c0623e1eaec6b80cc3656b6b603ce8fb00e2d3c4dbe6e7229b04b532a380e0e74f9fed778b4d82c79cfa77b114bdbffee1f43ac7190aeb6fa73dd23dbfbb88626e0360fbdc27fe470f16b552ecd78099cfb35a5975c4e78735254cb32eb9594f06f596ab345ecb6498e7d3df76d6b65e2ec7d60b28b289e0d2a87328aa2b39ae61eeb695fb795c3324ec65aa4330a07f7dfff41243cb82e62a632509ef598e16e92f90e08ee860dae6470f23b7dc1fd2379d3521957c613048689f09d91bb0d471a29a3ae59a4a17293bd4b94684d9d5958cb4579eb617a2650fcea19abea71b67ff703509cf4755c3195cc56b35f0d14fae458ee1f6941950e3bf0699159d6508b635c7fd6fabf613d822ca4739b53f01e714608c84ac19cc015f8af7e0ca489733e23f74bdccca00f76212d879b53bc19c13a039d0b644db6dc1c5a41cfd35f04dc53ef0ef98801789541c94b1648eddcb84142829b4d099c0fcf9eff6d581e5e730783a5bd124ad945d761544539a0243d5a6f90f0d6eafe13dc473f8c6602355915c310c4989dd09d6d2453552e8c7d5d2fcfe59716ae00719510a9f0a57bcae91b9265a281c8219d885ba72c6defde4399342e0b7a6d34eb4c2751b9a10b3f6f357deafc88297cc344b2073aa47c8c9e29c036cdb3bcc03a148a09792971671bc1c7113a4254d0c9403b82f9ded30aabbd5e8fd8b062e6c0d5b6b1928c542f7d2979f387319342db415cb360c554b86134c6a4eb0194f8b62bd56bd1fd67dd65deff31e94f28a71f2d0a1c067297840b084f0ff03612dd333b740acbcdc1ce5bff5ad8120712a761d203e797f30061d3156535843ea443f1745621199c0ae4e7a28237269a20cb743b453283899a6c874584e3e9c051b8d65358117e412d0c74c6605e79ee66d95f79de2c2253fbdc893ba669f55327a7b11fcee5eedcabfc33dd6a46c3c87771206b9010fa5b0ee19a7a227d428544d07613b62154f45f69c2e6c12052f018ced2598127268b5ada34621831d3d6707fba9462ff52343d2b810e9fda1b16b65ea3353515ab79a37334c8f766d0ed16607f174122b7da2a379799787190710cc990bec9f8c4be0799ddbbf878c2915628fccca34edaf2718cd26306f0f7dffea160355b0d4778f3baaeb44e2afe5fddd9ee0ea164fffe542a3f91ca2d9b7faf9e41fbc5ac6d92875e4dbb3b2fb88d2ddf8d1b2580f14beb976ceaf55510c583f0e2f3cd6ae566b92c28f43b9160811b0bdc1bcf2cb86fd10665a558eec2c7ecd68b6a7652f6fd47d1dbd2a6c110e9126c8d9289be588ea05379c9212687b5f15f424f5ccb02a46a9a873fc35a849a13fd452cfd01bfea1af20bd39f54e097e56399b5bb6e4d7d0a0a2864c3251cfd44eb90203f931efea6192ba3ff9c4f7eba2b0da14821e11c45dddb8dedbca1058eead6e7995df1f6237fe717c0e3f988c54dc84cb9876b4561b628f88e42a5e9d944bcab8cffa2038aeace0333ab833cd019050bb24fcb157fef6508cf53cb996c650c3ee2a8e5d5aca7d598bdd25ed4330e3d10e4afb7376fb464d97412de3589101c0487438c7e591e7be5f370703d3c927b7797ab62293653f4843490500edad7afd78577c7275522ea8faddb85a8ab96304bec7b6ae7063286839a87dbbd84254621a12bb9fdc9b26c84787e0439cd30e527b83be4cc4a957d64f6d35d6ef49c3597ea057e7f722a09a5975940ca233f844e855699548a41c78994c6ee0e81dd388aaf773c6a829b18d32624438b25043db3f6044d3587725da2896ba3e220ee87c82106fc166386db7fe931dd1ffa2fe5c5279ae25dc31c55f7cb1ddeb9ba0682709ee2083bccf796dc08c10fde4d371cef500fce9c81bed4f493089670ddebff9920a3dec6eeffbf0d510e494fa8581c364b1f72fd74ec90b5c0add947a3309c97a78f5a0dcb97b3c1ea2796d5b802b91931e048c776f8ef5b4867059247e59dbd7a039f28e2746cb6d02a34d75415471a87e6e8854abddf8d7b6a941e1c1b1615c00332849a04b3e21b6000c9131c81ff458703c13b5a7630119f8967179cfebc77538b73376ef7030163287afa0bd96209b1de2c2cc1749dab92781ee81ae8d72c3181a1d58f1526c9dd88e9d6a2f099b40cba6a076e191de98d30ad2b1e198b248f215879a403f11edb316e18fa050f30e22c119b2bc5b77fa918460c44035ee7aa1e56f6902c3a915c05ab5109067788111a092f2fbaf0cd4d0434d91012c428b3a8ff77e977b30594977e0e817c2cc44d3bb61f2049646e221c3efefec68f4e4a659aa5c1fe566d787b46fa73a56f9c39a557466c4aa6cec7f35ece0a1f7aba213df2785d2875cddcbafcaa6fe25694466bd37ae2c855534095e1d3738686763fa747a3ff56e7274d04755acf17c8db1f3c350e7f0c4fa5f3f5ed42071b40182e2d7557c8dee032c4f82f0907b31ac7328c0792a022dfd5fcfe8d07c3bb30f48b66405713db9ec2e283c39e1197184b65be1e8bf3c3d36a5160e1d0dd210728b0080190fdc2378a5b3eeb13256ce5b015262e86e24666c3d6dcebed253a60a6cd237a91b6ced4f9193a5c61c7e9fa2872a5a91c507281fa225dbff20000000000000000000000000000000000000000000000000000000000000000040b10171e22272b"

						if ctx.String("sigfile") != "" {
							sigfile, err := os.Open(ctx.String("sigfile"))
							if err != nil {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 71)
							}
							defer sigfile.Close()

							sigfileinfo, err := sigfile.Stat()
							if err != nil {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile"), 70)
							}
							if sigfileinfo.IsDir() {
								return cli.Exit("Could not open signature file "+ctx.String("sigfile")+" - is it a folder?", 72)
							}
							// load contents of sigfile into string
							sigfilebuffer := make([]byte, sigfileinfo.Size())
							_, err = sigfile.Read(sigfilebuffer)
							if err != nil {
								return cli.Exit("Could not read signature file "+ctx.String("sigfile"), 69)
							}
							signature = string(sigfilebuffer)
							// trim string to be correct signature length
							signature = signature[:9190]
						}
						pk := ctx.String("publickey")
						if ctx.String("pkfile") != "" {
							pkfile, err := os.Open(ctx.String("pkfile"))
							if err != nil {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile"), 71)
							}
							defer pkfile.Close()

							pkfileinfo, err := pkfile.Stat()
							if err != nil {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile"), 70)
							}
							if pkfileinfo.IsDir() {
								return cli.Exit("Could not open public key file "+ctx.String("pkfile")+" - is it a folder?", 72)
							}
							// load contents of pkfile into string
							pkfilebuffer := make([]byte, pkfileinfo.Size())
							_, err = pkfile.Read(pkfilebuffer)
							if err != nil {
								return cli.Exit("Could not read public key file "+ctx.String("pkfile"), 69)
							}
							pk = string(pkfilebuffer)
							pk = pk[:5184]
						}
						// pk := "da218daf9d5457bee0e2381250f7ad3159e8a243fbf90e02c2802e1722cee954758875aa00c57adda2736030ea7fd293367c202298d7125f4ca8bd83d0ee8e8805f4a9f2d3915d507a581d59a80491575ed69ed994a6650ecf8902cb056a6d5f8b59a46905ab1c58094c2a5a388de306486dbc23bf268ffa272e010182e8e9e23c07f55a866e59195333a353aeddf3cd51c22f955c21977d3ee9e4ee6557f30edb5d2517c04f834f6825a7a162323cb8b679cb5d2089190aa3e3c486b4b9895987b47e1b475ccc4f25969bc95ac24d2fb3cfcda7330ff9f949ac06a2b7a7293ee8463dc38a9c55d4bb5d8f4904836c29764931b0c3f4d1257871b132b08ae249fb40b61bb75360298f15345d4868b7aa4f06c485b703f6db84d2d5e1e70412928d6c6454a2a019540c518243e18e17404dfd781a576a34e0f297bc4fa69532e717cb9cadc1feafe4c6a99e31cde842dc05fd19d8c7131d530e9ab22b1c621e9d4a2ffd444376f0e0847c0523f56f345669fe88bb28492ed23dc822f83be85eb035695eceb08fb24fab3fb6cd54ee5972d68664af9d3bb4213da1ee11e95070eb45d033777eccf9efe54f2f23bdd0fd64cd0b4bd311d941f108fa13166505944de90e25fe50d4d4be8118d316994b53bacb96c92a4f4048e10fb01d7a8e89d7d0ba37f58ba37e1c399fd1d5c2fd0ba1d30231432a0592d0e06b0a18f0decaa3ef39e88c6d70b42bcc80e28f633c99a89e411d300ff78c7bc93f910906bc9d9202f4ce3b9a1c37432b4df23e053297f81b965ca0b1f447e323a2e66c9ffb75ab1c8daa2a9b239bd87bed1990f4dbf9747005950aa73b6a74da306342a63dfb67d5042f16814f08bd3fda8b572e501ce0a03111f93c0c1d3655634435f1ffc3fc000bf133c926bc336304eea648a7a1c7ebdd65fa593d5c11990878b385499a394584702fe309073aa15420e0d0980165ae7213dae40890babb2bbd3f7abf648c9dc74feba7c0ec8f0525bf5744744b9f5b28f6ac7f234e4f425f4bbafb69714abd911dd0514fd53039c13f72b1074f6c5a229f9172628747079193592bf74ac9049c2aed7823e9522ffeffb7d84887808a5e0814407ebbf514301fb015a3f0fa0c79d3fea883901f3bfc493569a239156f29364a1b43aeb4c3dc6a975ba517e1a6e8ca66b60e4de5326d2d65d95783b050546c73edc37175bf2dac38109c4cc6711c4f6ce4b7af5313e1967161841c11cbbd4f998d5d6b6b1135c9c75616ec88393300c199a2d602f6b048302258c6bf8960434ba6d3d6108a9d8fe17569c1454aedaa7b383975f3ecf1565df1e007744b9474111756a9b4471475dac9e55bb5eb1df67329aa077c14bb8aebac457ad06744e6b67238e1416e14a1c8c84d7981bb42b41562b10b9ba86809f47d19bb2c6a8a9f88559a9a73fecc7f95d781501095fd0f7493ecb020b35b613e2c91db655a9c85ae893e4da69e1ad833fb40c285f09992dbb6b18f154b198af34e3088928102e618722412934ff0bff977d9195d3eb520f8edb7cb08ffc9eeb0f60d02d8272652e456fdd28392acb41ce12fadc83c70dd742abd2015805f2b3713995d1d99050f08f9f88366cf5870b827dadc5bd20fdeacd672df857330be4e1b96838a0d8e97859fd7127d355e51ff9a5e43697b3cedaa1d62dd3aabe28fef97eae5cfec98399bc66f7a34616f95dcebf7eb6563a9115c13c46a80d564e669af08ce600ba0fec9f15a9422b1da6c3995cbff0212626c118ddf77721d84c938200bc9618e7234e3137053eb16620942e9632684e73163f0daad57327999e800c226a09c7083581e3b647cbd61e42a986ecb52f8e64e4d3efdb3fb942ebf2d1638a5c567115e6d33436e2f515e15b903e727d22c1945c968fd1ba1d87093e7768b75cd6033f2826580e85bd7c96477a62b1956a8f7aaba88d7ae095812acc9b9c33a477f3f920e49c7443bba90561b7804f6fe2bba598103507c61365bc11aea34f9f84c0e3a902eb6df4c292aead67699a63c1f5a4b87beb14b2e45537841902764b459b90ba378aadfdcd125deb953413fec2e3e1e3b4f6e435ae84cc7951b996a03db7e49cd1ddeda2041c99eff5dc9c85ffa383852ba9f9dde80cfe8c0353a6faa24a5ae307b8bd863c14f6a9b5b75daf8534118131b3b32b8239f51f6d5123ced24e9bd251d208ca40fa97f9e47fa79f25ede38280a5206c10281a8d4a8459fb0fe9dece2cc61f1ced84e7b5744e59312e32de10c82be7f81264d3a775a04913ce7bb1f28c25037f4b3b2ad5790b3667c9e309234cd161c36f7a71a0145ff0a7c9c1b9bed601b4971696c1979ac3ae2418a842e50c33ed45fddd0e319e48f72583cb90a4b08a57983f63918352cbc6f0a6d345c845f0f2cfbebc25cef454dfcdde04966e63e37d0b2060a12bdedfe3758c5f38a3c7250271ce9dded0e2c37304bbf668add831f76902d42041b9e7a2d77e9e912980be070a0dd84f3523055a86d84b7d92282974ec8f411e26aa88286b6a1314ea9a0b3d3ab100947770238d6a714d0e2ac9a1b7b3cff7e54c33d8bf7a40972418dc7fb205d7c29a8ad0a269eb9f0874e1ae2d37485e9fac92bce8c267d2feaa63f1fe186ae0cd25b626246b2db984941fa6eeb2b2ab14a56aaf15da2458b591b4862173a917a404725b9fee25539b948b2e2c9c5f2a251e9f88cd301715aa221e710228a0e1c691e0ea91414d7ddc6cbe76b572dd904b8107e4472e5e0d694ec8e4cf29c79ca83206c9a8fcb8e77a1157b4f7c9a68ab41520b5e2c0c9af6d11109c259ab5dc8d1f87bc83ebeb4a8845519833e42883ad7b16752b2ffbdc53ececca688b97b431a33d4223dcc32be985ea66f255ae44df027713ae10120e3bcc2eac966d974cc6e69449e959d7eb783855f975d36a8a5d5889db3137b338cabba16284d87965493bb07cc5639bb017499d5a59049a65fd5a0a58568c8c93677491b45b3099dd3ab9527dcb9455d42e7c22278dd800187a8fa016ad0ae3a5737f5ac6fbec043576cf5298150daba87066fb20ee074dfbfb330f4d9321834b35b43e9448997b254e78e1f2c5a4d757e4dc5bfee53dedcc863c539273d7135b063b724bc0edf153fd1f2828866801673c068442b38bcf45ea3bc006b84aaef5e8cc1de1d00e10484b3a59546c4b729595bde6a7facb5e1f6a041dd52307ec9ca2d1ca891eca2e2f0803ddac1698d6cc07d4ee381c06e9d232676c1acfa03287000c44afdf6c1613fa3ae499acd852f8a43dee5f2f790ab6b56a3010d6f35b6d0d3d185540f21593b8d8e75c4938192706ae087555ebc1e48882f1ee46af8256964d7fd4fb9bb6ffa60f79036b17e46d7f210c25fb1690a748dcf33ae74b1f44290fe1a46b87333def13630cc17e7e1290593775b043f817e603675dd16ceb159b4ee6d43799c2ae23984465e0942a64e30da1271d5e6194585d3ecdfe2302d4cae4ca388a516184e333f0d87103ab6585a955be8c7708c338fe1775b04486721b008cf99fd1f6d1a0d1027d975b21086fd42d4037f7979eac9e22108432401aff3443c5aec62e5a7c44bcda3d0ccc0e1b56c611f69b84500d2649f852190eedd1eb9a121d476dd26f81c6a52859c1de36066e8ce44a9f2edf94717b0fe445caddb"
						verified, err := verify.VerifyFile(file, signature, pk)
						if err != nil {
							fmt.Printf("Error: %a", err)
							return cli.Exit("Error when verifying "+file, 79)
						}
						if verified {
							return cli.Exit("Signature is valid", 0)
						}
						if !verified {
							return cli.Exit("Signature is not valid", 1)
						}
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "sign",
				Usage: "signs a file with a dilithium signature [eg. qrlft sign --hexseed=f29f58aff0b00de2844f7e20bd9eeaacc379150043beeb328335817512b29fbb7184da84a092f842b2a06d72a24a5d28 doc.txt]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "hexseed",
						Aliases: []string{"hs"},
						Usage:   "Signs file using the private key `SEED`",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the signature, no filename",
					},
				},
				Action: func(ctx *cli.Context) error {
					if ctx.String("hexseed") == "" {
						return cli.Exit("No hexseed provided", 78)
					}
					hexseed := ctx.String("hexseed")
					files := ctx.Args().Slice()
					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					if len(files) == 1 {
						files, _ = filepath.Glob(files[0])
					}
					for _, file := range files {
						file := file

						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when signing "+file+" - "+err.Error(), 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when signing "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						signature, err := sign.SignFile(file, hexseed)
						if err != nil {
							fmt.Printf("Error: %a", err)
							return cli.Exit("Error when signing "+file, 79)
						}
						output(file, signature, ctx.Bool("quiet"))
					}
					return cli.Exit("", 0)
				},
			},
			{
				Name:  "hash",
				Usage: "hashes a file with algorithm selected in options [eg. qrlft hash --sha256 doc.txt]",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "sha3-512",
						Usage: "hash with SHA3-512",
					},
					&cli.BoolFlag{
						Name:  "keccak-256",
						Usage: "hash with Keccak-256",
					},
					&cli.BoolFlag{
						Name:  "keccak-512",
						Usage: "hash with Keccak-512",
					},
					&cli.BoolFlag{
						Name:  "sha256",
						Usage: "hash with SHA256",
					},
					&cli.BoolFlag{
						Name:  "sha1",
						Usage: "hash with SHA1",
					},
					&cli.BoolFlag{
						Name:  "md5",
						Usage: "hash with MD5",
					},
					&cli.BoolFlag{
						Name:  "crc32",
						Usage: "hash with CRC32",
					},
					&cli.BoolFlag{
						Name:  "blake2s",
						Usage: "hash with BLAKE2s",
					},
					&cli.BoolFlag{
						Name:  "quiet",
						Usage: "just output the hash, no filename",
					},
					&cli.BoolFlag{
						Name:    "string",
						Aliases: []string{"s"},
						Usage:   "hash a string instead of a file [eg. qrlft hash --sha256 HashThisText]",
					},
				},
				Action: func(ctx *cli.Context) error {
					action := false
					files := ctx.Args().Slice()

					if ctx.Bool("string") {
						if ctx.Bool("sha256") {
							return cli.Exit(hash.SHA256string(files[0]), 0)
						}
						if ctx.Bool("sha1") {
							return cli.Exit(hash.SHA1string(files[0]), 0)
						}
						if ctx.Bool("md5") {
							return cli.Exit(hash.MD5string(files[0]), 0)
						}
						if ctx.Bool("crc32") {
							return cli.Exit(hash.CRC32string(files[0]), 0)
						}
						if ctx.Bool("sha3-512") {
							return cli.Exit(hash.SHA3512string(files[0]), 0)
						}
						if ctx.Bool("keccak-256") {
							return cli.Exit(hash.Keccak256string(files[0]), 0)
						}
						if ctx.Bool("keccak-512") {
							return cli.Exit(hash.Keccak512string(files[0]), 0)
						}
						if ctx.Bool("blake2s") {
							return cli.Exit(hash.Blake2s256string(files[0]), 0)
						}
					}

					if len(files) == 0 {
						return cli.Exit("No file provided", 82)
					}
					if len(files) == 1 && !ctx.Bool("string") {
						files, _ = filepath.Glob(files[0])
					}
					for _, file := range files {
						file := file
						filecheck, err := os.Open(file)
						if err != nil {
							return cli.Exit("Error when hashing "+file+" - "+err.Error(), 78)
						}
						defer filecheck.Close()

						fileinfo, err := filecheck.Stat()
						if err != nil {
							return cli.Exit("Error when hashing "+file, 77)
						}
						if fileinfo.IsDir() {
							// skip this iteration
							continue
						}
						// sha3-512
						if ctx.Bool("sha3-512") {
							x, err := hash.SHA3512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-256
						if ctx.Bool("keccak-256") {
							x, err := hash.Keccak256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// keccak-512
						if ctx.Bool("keccak-512") {
							x, err := hash.Keccak512sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha256
						if ctx.Bool("sha256") {
							x, err := hash.SHA256sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// md5
						if ctx.Bool("md5") {
							x, err := hash.MD5sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// crc32
						if ctx.Bool("crc32") {
							x, err := hash.CRC32(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// sha1
						if ctx.Bool("sha1") {
							x, err := hash.SHA1sum(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}

						// blake2s
						if ctx.Bool("blake2s") {
							x, err := hash.Blake2s256(file)
							// if file doesn't exist return an error
							if err != nil {
								return cli.Exit("File "+file+" not found", 83)
							}
							output(file, x, ctx.Bool("quiet"))
							action = true
						}
					}

					if action {
						return cli.Exit("", 0)
					}
					return cli.Exit("No action selected", 84)
				},
			},
			{
				Name:  "salt",
				Usage: "generates user-specified bytes random salt [eg. qrlft salt 16]",
				Action: func(ctx *cli.Context) error {
					saltSize, _ := strconv.Atoi(ctx.Args().Get(0))
					if saltSize == 0 {
						return cli.Exit("Please specify a salt size: [eg: qrlft salt 16]", 81)
					}
					salt := generateRandomSalt(saltSize)
					if !ctx.Bool("quiet") {
						fmt.Printf("Generating random %d bytes of salt as a hexstring\n", saltSize)
					}
					fmt.Printf("%s\n", hex.EncodeToString(salt))
					return cli.Exit("", 0)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
