package co.zlh.fhcpabe;
import java.util.ArrayList;
import it.unisa.dia.gas.jpbc.Element;

public class FhcpabePolicy {
    /* serialized */

    /* k=1 if leaf, otherwise threshould */
    int k;
    /* attribute string if leaf, otherwise null */
    String attr;
    Element c;			/* G_1 only for leaves */
    Element cp;		/* G_1 only for leaves */

    public Element c_hat; /* G_T only for level node*/
    public Element cs; /* G_1 only for level node*/

    /* array of BswabePolicy and length is 0 for leaves */
    FhcpabePolicy[] children;
    int level_num ;
    /* only used during encryption */
    FhcpabePolynomial q;

    /* only used during decription */
    boolean satisfiable;
    int min_leaves;
    int attri;
    ArrayList<Integer> satl = new ArrayList<Integer>();
    Element ck;
}
