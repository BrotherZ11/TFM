import slixmpp

import asyncio

from slixmpp.xmlstream import ET

from pqc_wrapper import PQCProvider



NS = "urn:uma:tfm:pqc:0"





class EmisorPQC(slixmpp.ClientXMPP):

    def __init__(self, jid, password, recipient, alg_name):

        super().__init__(jid, password)



        # Para WSL/local demo (sin TLS). OJO: solo laboratorio.

        self.use_tls = False

        self.use_ssl = False

        self.force_starttls = False

        self["feature_mechanisms"].unencrypted_plain = True



        self.recipient = recipient

        self.pqc = PQCProvider()

        self.alg_name = alg_name



        self.add_event_handler("session_start", self.start)



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



        # pequeño margen para estabilizar sesión (evita carreras)

        await asyncio.sleep(0.2)



        cuerpo = "Este es un mensaje firmado con " + self.alg_name

        print(f"Firmando con {self.alg_name}...")



        data = self.pqc.sign_message(self.alg_name, cuerpo.encode("utf-8"))



        msg = self.make_message(mto=self.recipient, mbody=cuerpo, mtype="chat")



        # Construir elemento PQC: <pqc_auth alg="..."><sig>..</sig><pk>..</pk></pqc_auth>

        pqc_tag = ET.Element(f"{{{NS}}}pqc_auth")

        pqc_tag.set("alg", self.alg_name)



        sig_el = ET.SubElement(pqc_tag, f"{{{NS}}}sig")

        sig_el.text = data["sig"]



        pk_el = ET.SubElement(pqc_tag, f"{{{NS}}}pk")

        pk_el.text = data["pk"]



        msg.xml.append(pqc_tag)



        xml_str = ET.tostring(msg.xml, encoding="utf-8")

        print("Tamaño stanza:", len(xml_str), "bytes")



        msg.send()

        print("Mensaje enviado (send()). Mantengo conexión unos segundos...")



        # mantener conexión para asegurar entrega

        await asyncio.sleep(5)

        self.disconnect()





if __name__ == "__main__":

    import sys



    alg = sys.argv[1] if len(sys.argv) > 1 else "SPHINCS+-SHA2-128s-simple"



    bot = EmisorPQC("emisor@localhost", "123", "receptor@localhost", alg)

    bot.register_plugin("xep_0030")  # Service Discovery (no imprescindible)

    bot.connect(host="localhost", port=5222)

    bot.loop.run_forever()

