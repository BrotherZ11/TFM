import slixmpp

from slixmpp.xmlstream import ET

from crypto.pqc_wrapper import PQCProvider

import time



NS = "urn:uma:tfm:pqc:0"





class ReceptorPQC(slixmpp.ClientXMPP):

    def __init__(self, jid, password):

        super().__init__(jid, password)



        # Para WSL/local demo (sin TLS). OJO: solo laboratorio.

        self.use_tls = False

        self.use_ssl = False

        self.force_starttls = False

        self["feature_mechanisms"].unencrypted_plain = True



        self.pqc = PQCProvider()



        self.add_event_handler("session_start", self.start)

        self.add_event_handler("message", self.on_message)



        # Debug crudo del socket

        self.add_event_handler("raw_in", self.raw_in)

        self.add_event_handler("raw_out", self.raw_out)



    def raw_in(self, data):

        if "pqc_auth" in data:

            print(f"[RAW_IN] pqc_auth bytes={len(data)}")



    def raw_out(self, data):

        if "pqc_auth" in data:

            print(f"[RAW_OUT] pqc_auth bytes={len(data)}")



    async def start(self, event):

        self.send_presence()

        await self.get_roster()

        print("Receptor listo y esperando mensajes...")



    def on_message(self, msg):

        if msg["type"] not in ("chat", "normal"):

            return



        # Debug del XML completo (útil si no encuentra la etiqueta)

        xml_bytes = ET.tostring(msg.xml, encoding="utf-8")

        print(f"\n[DEBUG] Stanza recibida bytes={len(xml_bytes)} from={msg['from']} id={msg['id']}")



        pqc_data = msg.xml.find(f"{{{NS}}}pqc_auth")

        if pqc_data is None:

            print("[DEBUG] No pqc_auth en este mensaje.")

            return



        alg = pqc_data.get("alg")



        sig_el = pqc_data.find(f"{{{NS}}}sig")

        pk_el = pqc_data.find(f"{{{NS}}}pk")



        signature = sig_el.text.strip() if sig_el is not None and sig_el.text else None

        pk = pk_el.text.strip() if pk_el is not None and pk_el.text else None



        if not alg or not signature or not pk:

            print("[DEBUG] pqc_auth incompleto (alg/sig/pk).")

            return



        start_v = time.perf_counter()

        is_valid = self.pqc.verify_signature(alg, msg["body"].encode("utf-8"), signature, pk)

        end_v = time.perf_counter()



        print(f"[NUEVO MENSAJE] de {msg['from']}")

        print(f"Cuerpo: {msg['body']}")

        print(f"Algoritmo: {alg}")

        print(f"Verificación: {'VÁLIDA' if is_valid else 'ERROR'}")

        print(f"Tiempo Verificación: {(end_v - start_v) * 1000:.2f} ms")





if __name__ == "__main__":

    bot = ReceptorPQC("receptor@localhost", "123")

    bot.connect(host="10.255.255.254", port=5222)

    bot.loop.run_forever()