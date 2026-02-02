import oqs

import base64





class PQCProvider:

    """

    Firma/verificación PQC con oqs-python (liboqs).

    - Genera keypair por mensaje (para demo). En el TFM luego puedes cambiar a:

      - keypair persistente por identidad (más realista).

    """



    def sign_message(self, alg_name: str, message_bytes: bytes) -> dict:

        with oqs.Signature(alg_name) as sig:

            public_key = sig.generate_keypair()

            signature = sig.sign(message_bytes)

            return {

                "pk": base64.b64encode(public_key).decode("ascii"),

                "sig": base64.b64encode(signature).decode("ascii"),

            }



    def verify_signature(self, alg_name: str, message_bytes: bytes, signature_b64: str, pk_b64: str) -> bool:

        try:

            sig_bytes = base64.b64decode(signature_b64.encode("ascii"))

            pk_bytes = base64.b64decode(pk_b64.encode("ascii"))

            with oqs.Signature(alg_name) as sig:

                return sig.verify(message_bytes, sig_bytes, pk_bytes)

        except Exception as e:

            print("ERROR verify_signature:", repr(e))

            return False