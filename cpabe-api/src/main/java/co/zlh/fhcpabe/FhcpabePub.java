package co.zlh.fhcpabe;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;


public class FhcpabePub {
    /*
     * A public key
     */
    public String pairingDesc;
    public Pairing p;
    public Element g;				/* G_1 */
    public Element h;				/* G_1 */
    public Element g_hat_alpha;	/* G_T */

    //only for test
//    public Element r;
//    public Element egg;
//    public Element beta;
}
