library aws_cloudfront_signed_url;

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import "package:pointycastle/export.dart";
import 'package:rsa_encrypt/rsa_encrypt.dart' as rsaencrypt;

/// Used to create CloudFront signed urls using custom policy
/// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html
class AWSCloudFrontSignedUrl {
  /// The ID for a CloudFront public key, for example, K2JCJMDEHXQW5F.
  final String keyPairId;

  /// CloudFront private key
  /// The private key whose public key is in an active trusted key group for the distribution
  /// Usually starts with -----BEGIN RSA PRIVATE KEY-----
  final String privateKey;

  /// Used to create CloudFront signed urls using custom policy
  /// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-custom-policy.html
  const AWSCloudFrontSignedUrl({
    @required this.keyPairId,
    @required this.privateKey,
  });

  /// ***[resourceUrl]*** The base URL including your query strings, if any, for example:
  /// http://d111111abcdef8.cloudfront.net/images/horizon.jpg?size=large&license=yes
  ///
  /// ***[dateLessThan]*** The expiration date and time for the URL,
  /// This parameter is required by CloudFront,
  /// if parameter not passed it will be set to DateTime(2080)
  ///
  /// ***[dateGreaterThan]*** (Optional) An optional start date and time for the URL,
  /// Users are not allowed to access the file before the specified date and time.
  ///
  /// ***[ipAddress]*** (Optional) The IP address of the client making the GET request
  /// (for example, 192.0.2.0/24)
  Future<String> signUrl({
    @required String resourceUrl,
    DateTime dateLessThan,
    DateTime dateGreaterThan,
    String ipAddress,
  }) async {
    final String policyStatement = _createPolicyStatement(
      resourceUrl: resourceUrl,
      dateLessThan: dateLessThan,
      dateGreaterThan: dateGreaterThan,
      ipAddress: ipAddress,
    );

    final String base64EncodedPolicy = _encodePolicyStatement(policyStatement: policyStatement);

    final String policySignature = _createSignature(policyStatement: policyStatement);

    return _createSignedUrl(
      resourceUrl: resourceUrl,
      base64EncodedPolicy: base64EncodedPolicy,
      policySignature: policySignature,
    );
  }

  String _createPolicyStatement({
    @required String resourceUrl,
    DateTime dateLessThan,
    DateTime dateGreaterThan,
    String ipAddress,
  }) {
    Map<String, Map<String, dynamic>> conditions = {};

    if (dateLessThan == null) dateLessThan = DateTime(2080);
    final int dateLessThanEpochTime = dateLessThan.millisecondsSinceEpoch ~/ 1000;
    conditions["DateLessThan"] = {"AWS:EpochTime": dateLessThanEpochTime};

    if (dateGreaterThan != null) {
      final int dateGreaterThanEpochTime = dateGreaterThan.millisecondsSinceEpoch ~/ 1000;
      conditions["DateGreaterThan"] = {"AWS:EpochTime": dateGreaterThanEpochTime};
    }
    if (ipAddress != null) {
      conditions["IpAddress"] = {"AWS:SourceIp": ipAddress};
    }

    final String conditionsJson = json.encode(conditions);

    final String policyStatement =
        '{"Statement":[{"Resource":"$resourceUrl","Condition":$conditionsJson}]}';
    return policyStatement;
  }

  String _createSignedUrl({
    @required String resourceUrl,
    @required String base64EncodedPolicy,
    String policySignature,
  }) {
    return resourceUrl +
        "?Policy=" +
        base64EncodedPolicy +
        "&Signature=" +
        policySignature +
        "&Key-Pair-Id=" +
        keyPairId;
  }

  String _createSignature({@required String policyStatement}) {
    RSAPrivateKey rsaPrivateKey =
        rsaencrypt.RsaKeyHelper().parsePrivateKeyFromPem(privateKey.replaceAll(" ", ""));
    var signer = RSASigner(SHA1Digest(), "06052b0e03021a");
    signer.init(true, PrivateKeyParameter<RSAPrivateKey>(rsaPrivateKey));
    var signedBytes = signer.generateSignature(Uint8List.fromList(policyStatement.codeUnits));
    var signedText = base64Encode(signedBytes.bytes);
    String formattedBase64Signature =
        signedText.replaceAll('+', '-').replaceAll('=', '_').replaceAll('/', '~');
    return formattedBase64Signature;
  }

  String _encodePolicyStatement({@required String policyStatement}) {
    final policy = utf8.encode(policyStatement);
    String base64EncodedPolicy =
        base64Encode(policy).replaceAll('+', '-').replaceAll('=', '_').replaceAll('/', '~');
    return base64EncodedPolicy;
  }
}
