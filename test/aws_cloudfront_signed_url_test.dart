import 'dart:convert';

import 'package:aws_cloudfront_signed_url/aws_cloudfront_signed_url.dart';
import 'package:flutter_test/flutter_test.dart';

const String _privateKey = '''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDUvnZReDyX/DqTXQa30028TqkklaDEay0Yn9rcXlE8JqD6+CLp
T4HXziLUZhw8RsPV67fTdLIhsx/XBWfOM4IxOrsyZ9Y5WlVSLsc3cRhwx2Kbzrej
sChQKwzgR+uRMZbEGSng8fuKl5WqEOnI6PsRhrM/ckos6R537VwO/ycEYwIDAQAB
AoGBAMYiDDeb73LtKfCMtvEFDmTOLaEw6WWFG57PYhnSjX2jzFFwP7NipN7D0JRX
9Pv+O+1DdxSsninclU7AbgkQ17IljkrLWTGW6Tg1Sb21rAm0EAhN2gTfgXOhTfUc
7Zw53wYKdZTRsFPHlpqtYl885zHU0eNO+taEP7RbzG+9co/hAkEA/QnJWpFfghbg
eZYoWKe8r4rGADW4gMRvk1PQq3xuNIBB3Cd0lpJgzvXM34MMJILYozevEFma+uuf
fx6S2It6zwJBANc777sHOaQOQ62RE+4BAURPxbWq9eYy/iivp93riH3WcBRTrV72
c+vpymtpZv1iO5+JfQSvKsXKUoCGFLZ6Mi0CQDLaa6gS/UHUvSpSXitrEoWo+yAB
q+HdGJtgRdig+jj86b+IAmtcYa5WQeVNnfwce9NZlopPp9Dz16shhtuUNIsCQHFD
oUyS6Mpkl0jnZ81/yeLg9/I6HV0eyJEwnu4x3IocJq8LudiXaTlktpj/xqrg3u99
ssScSa38Yp4v8QZ2F6ECQAekSkDGKzlZG7uD1wdlaU8cjWn7h6EcpBdw9Hn2oOCT
C8KdHgenfZXdpypf/Ro4Okt/8UPqDa1Rj9PHy9TRYPc=
-----END RSA PRIVATE KEY-----''';

void main() {
  const AWSCloudFrontSignedUrl signer = AWSCloudFrontSignedUrl(
    keyPairId: 'test-key-pair',
    privateKey: _privateKey,
  );

  test('creates a signed URL with all custom policy conditions', () async {
    const String resourceUrl = 'https://example.cloudfront.net/image.jpg';
    final DateTime dateLessThan = DateTime.utc(2030);
    final DateTime dateGreaterThan = DateTime.utc(2025);

    final String signedUrl = await signer.signUrl(
      resourceUrl: resourceUrl,
      dateLessThan: dateLessThan,
      dateGreaterThan: dateGreaterThan,
      ipAddress: '192.0.2.0/24',
    );

    final Map<String, String> parameters = Uri.parse(signedUrl).queryParameters;
    final Map<String, dynamic> policy = _decodePolicy(parameters['Policy']!);
    final Map<String, dynamic> statement =
        (policy['Statement'] as List<dynamic>).single as Map<String, dynamic>;

    expect(parameters['Key-Pair-Id'], 'test-key-pair');
    expect(parameters['Signature'], isNotEmpty);
    expect(statement['Resource'], resourceUrl);
    expect(statement['Condition'], <String, dynamic>{
      'DateLessThan': <String, dynamic>{
        'AWS:EpochTime': dateLessThan.millisecondsSinceEpoch ~/ 1000,
      },
      'DateGreaterThan': <String, dynamic>{
        'AWS:EpochTime': dateGreaterThan.millisecondsSinceEpoch ~/ 1000,
      },
      'IpAddress': <String, dynamic>{'AWS:SourceIp': '192.0.2.0/24'},
    });
  });

  test('allows optional custom policy conditions to be omitted', () async {
    final String signedUrl = await signer.signUrl(
      resourceUrl: 'https://example.cloudfront.net/image.jpg',
    );

    final String encodedPolicy =
        Uri.parse(signedUrl).queryParameters['Policy']!;
    final Map<String, dynamic> policy = _decodePolicy(encodedPolicy);
    final Map<String, dynamic> statement =
        (policy['Statement'] as List<dynamic>).single as Map<String, dynamic>;

    expect(statement['Condition'], <String, dynamic>{
      'DateLessThan': <String, dynamic>{
        'AWS:EpochTime': DateTime(2080).millisecondsSinceEpoch ~/ 1000,
      },
    });
  });
}

Map<String, dynamic> _decodePolicy(String encodedPolicy) {
  final String base64Policy = encodedPolicy
      .replaceAll('-', '+')
      .replaceAll('_', '=')
      .replaceAll('~', '/');
  return jsonDecode(utf8.decode(base64Decode(base64Policy)))
      as Map<String, dynamic>;
}
