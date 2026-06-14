library;

import 'package:plugin_crypto/src/crypto/models/key_types.dart';


const validMlKem512Spec = MlKemKeySpec(MlKemParameterSet.mlKem512);
const validMlKem768Spec = MlKemKeySpec(MlKemParameterSet.mlKem768);
const validMlKem1024Spec = MlKemKeySpec(MlKemParameterSet.mlKem1024);


const validMlDsa44Spec = MlDsaKeySpec(MlDsaParameterSet.mlDsa44);
const validMlDsa65Spec = MlDsaKeySpec(MlDsaParameterSet.mlDsa65);
const validMlDsa87Spec = MlDsaKeySpec(MlDsaParameterSet.mlDsa87);


final allValidMlKemSpecs = [
  validMlKem512Spec,
  validMlKem768Spec,
  validMlKem1024Spec,
];

final allValidMlDsaSpecs = [
  validMlDsa44Spec,
  validMlDsa65Spec,
  validMlDsa87Spec,
];
