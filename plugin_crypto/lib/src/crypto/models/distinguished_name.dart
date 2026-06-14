library;

class DistinguishedName {
  final String commonName;
  final String? organization;
  final String? organizationalUnit;
  final String? locality;
  final String? state;
  final String? country;

  const DistinguishedName({
    required this.commonName,
    this.organization,
    this.organizationalUnit,
    this.locality,
    this.state,
    this.country,
  });

  void validate() {
    if (commonName.isEmpty) {
      throw ArgumentError('DistinguishedName.commonName must be non-empty');
    }

    if (country != null) {
      if (country!.length != 2) {
        throw ArgumentError(
          'DistinguishedName.country must be exactly 2 characters, '
          'got "${country!}" (${country!.length} chars)',
        );
      }
      for (var i = 0; i < country!.length; i++) {
        final c = country!.codeUnitAt(i);
        if (c < 65 || c > 90) {
          throw ArgumentError(
            'DistinguishedName.country must contain only uppercase ASCII '
            'letters A-Z, got "${country!}"',
          );
        }
      }
    }
  }

  List<(String, String)> get entries {
    final result = <(String, String)>[];
    if (country != null) result.add(('C', country!));
    if (state != null) result.add(('ST', state!));
    if (locality != null) result.add(('L', locality!));
    if (organization != null) result.add(('O', organization!));
    if (organizationalUnit != null) result.add(('OU', organizationalUnit!));
    result.add(('CN', commonName));
    return result;
  }
}
