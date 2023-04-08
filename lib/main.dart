import 'dart:convert';
import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:pointycastle/api.dart' as c;
import 'package:pointycastle/asymmetric/api.dart';
import 'package:pointycastle/asymmetric/oaep.dart';
import 'package:pointycastle/asymmetric/rsa.dart';
import 'package:pointycastle/key_generators/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/random/fortuna_random.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.pink,
      ),
      home: const MyHomePage(),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key});

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final TextEditingController controller = TextEditingController();
  late final keyPair;
  late final publicKey;
  late final privateKey;
  bool encripo = false;
  String? cadena;
  c.AsymmetricKeyPair<c.PublicKey, c.PrivateKey> generateRSAKeyPair() {
    final secureRandom = FortunaRandom();
    final seedSource = Random.secure();
    final seeds = <int>[];
    for (var i = 0; i < 32; i++) {
      seeds.add(seedSource.nextInt(255));
    }
    secureRandom.seed(c.KeyParameter(Uint8List.fromList(seeds)));

    final keyParams =
        RSAKeyGeneratorParameters(BigInt.parse('65537'), 2048, 12);
    final keyGenerator = RSAKeyGenerator();
    keyGenerator.init(c.ParametersWithRandom(keyParams, secureRandom));

    return keyGenerator.generateKeyPair();
  }

  String encryptRSA(String inputText, c.PublicKey publicKey) {
    final plainText = Uint8List.fromList(utf8.encode(inputText));

    final encryptor = OAEPEncoding(RSAEngine())
      ..init(true, c.PublicKeyParameter<RSAPublicKey>(publicKey));
    final cipherText = encryptor.process(plainText);

    return base64.encode(cipherText);
  }

  String decryptRSA(String cipherText, c.PrivateKey privateKey) {
    final cipher = base64.decode(cipherText);

    final decryptor = OAEPEncoding(RSAEngine())
      ..init(false, c.PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final plainText = decryptor.process(cipher);

    return utf8.decode(plainText);
  }

  @override
  void initState() {
    keyPair = generateRSAKeyPair();
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;

    //cadena = encryptRSA(inputText, publicKey);

    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 20),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Text(
              "Algoritmo de encriptacionRSA",
              style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: Colors.pink),
            ),
            const SizedBox(height: 100),
            TextField(
              decoration: const InputDecoration(label: Text("Texto")),
              controller: controller,
              onChanged: (value) {
                setState(() {});
              },
            ),
            const SizedBox(height: 50),
            Text(cadena ?? "Sin texto"),
            const SizedBox(height: 50),
            GestureDetector(
              onTap: () {
                if (controller.text.isNotEmpty) {
                  if (encripo) {
                    setState(() {
                      cadena = decryptRSA(cadena!, privateKey);
                      encripo = false;
                    });
                  } else {
                    setState(() {
                      encripo = true;
                      cadena = encryptRSA(controller.text, publicKey);
                    });
                  }
                }
              },
              child: Container(
                alignment: Alignment.center,
                width: double.infinity,
                height: 50,
                decoration: BoxDecoration(
                    color: (controller.text.isNotEmpty)
                        ? Colors.pink
                        : Colors.grey),
                child: Text(
                  (encripo) ? "Desencriptar" : "Encriptar",
                  style: const TextStyle(color: Colors.white),
                ),
              ),
            )
          ],
        ),
      ),
    );
  }
}
