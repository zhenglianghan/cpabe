package co.zlh.fhcpabe;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
public class Fhcpabe {
    private static String curveParams = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

    public  static void setup(FhcpabePub pub ,FhcpabeMsk msk){
        Element alpha;

        CurveParameters params = new DefaultCurveParameters()
                .load(new ByteArrayInputStream(curveParams.getBytes()));

        pub.pairingDesc = curveParams;
        pub.p = PairingFactory.getPairing(params);
        Pairing pairing = pub.p;
        pub.g = pairing.getG1().newElement();
        pub.h = pairing.getG1().newElement();
        pub.g_hat_alpha = pairing.getGT().newElement();
        alpha = pairing.getZr().newElement();
        msk.beta = pairing.getZr().newElement();
        msk.g_alpha = pairing.getG1().newElement();

        alpha.setToRandom();
        msk.beta.setToRandom();
        pub.g.setToRandom();

        msk.g_alpha = pub.g.duplicate();
        msk.g_alpha.powZn(alpha);

        pub.h = pub.g.duplicate();
        pub.h.powZn(msk.beta);

        pub.g_hat_alpha= pairing.pairing(pub.g,msk.g_alpha);

//        pub.egg = pairing.pairing(pub.g,pub.g);//test
//        pub.beta = msk.beta.duplicate();


    }

    public static FhcpabePrv keygen(FhcpabePub pub, FhcpabeMsk msk, String[] attrs) throws NoSuchAlgorithmException{
        FhcpabePrv prv = new FhcpabePrv();
        Element g_r, r;
        Pairing pairing;

        /* initialize */
        pairing = pub.p;
        prv.d = pairing.getG1().newElement();
        g_r = pairing.getG1().newElement();
        r = pairing.getZr().newElement();

        /*compute*/
        r.setToRandom();
//        pub.r = r;//test
        g_r = pub.g.duplicate();
        g_r.powZn(r);

        prv.d = pub.h.duplicate();
        prv.d.powZn(r);
        prv.d.mul(msk.g_alpha);

        int i, len = attrs.length;
        prv.comps = new ArrayList<FhcpabePrvComp>();
        for(i = 0; i<len; i++)
        {
            FhcpabePrvComp comp = new FhcpabePrvComp();
            Element h_j_rj;
            Element rj;

            comp.attr = attrs[i];

            comp.d = pairing.getG1().newElement();
            comp.dp = pairing.getG1().newElement();
            h_j_rj = pairing.getG1().newElement();
            rj = pairing.getZr().newElement();

            elementFromString(h_j_rj,comp.attr);
            rj.setToRandom();
            h_j_rj.powZn(rj);

            comp.d = g_r.duplicate();
            comp.d.mul(h_j_rj);
            comp.dp = pub.h.duplicate();
            comp.dp.powZn(rj);

            prv.comps.add(comp);
        }
        return  prv;
    }

    public static FhcpabeCphKey enc(FhcpabePub pub, String policy) throws Exception{
        FhcpabeCphKey keyCph = new FhcpabeCphKey();
        FhcpabeCph cph = new FhcpabeCph();
        cph.p = parsePolicyPostfix(policy);
        Pairing pairing = pub.p;
        Element s;
        ArrayList<Element> cks = new ArrayList<Element>();

        s = pairing.getZr().newElement();
        s.setToRandom();

        fillPolicy(cph.p, pub, s,cks);

        keyCph.cph = cph;
        keyCph.cks = cks;

        return keyCph;

    }

    public static void dec(FhcpabePub pub,FhcpabePrv prv,FhcpabeCph cph){
        Element t;
        t = pub.p.getGT().newElement();
        checkSatisfy(cph.p,prv);

        pickSatisfyMinLeaves(cph.p, prv);

        decFlatten(t, cph.p, prv, pub);
    }










    private static void elementFromString(Element h, String s)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(s.getBytes());
        h.setFromHash(digest, 0, digest.length);
    }

    private static FhcpabePolicy parsePolicyPostfix(String s) throws Exception {
        String[] toks;
        String tok;
        ArrayList<FhcpabePolicy> stack = new ArrayList<FhcpabePolicy>();
        FhcpabePolicy root ;
        int level_num = 0;
        toks = s.split(" ");

        int toks_cnt = toks.length;
        for (int index = 0; index < toks_cnt; index++) {
            int i, k, n;

            tok = toks[index];
            if (!tok.contains("of")) {
                stack.add(baseNode(1, tok));
            } else {
                FhcpabePolicy node;
                level_num++;

                /* parse kof n node */
                String[] k_n = tok.split("of");
                k = Integer.parseInt(k_n[0]);
                n = Integer.parseInt(k_n[1]);

                if (k < 1) {
                    System.out.println("error parsing " + s
                            + ": trivially satisfied operator " + tok);
                    return null;
                } else if (k > n) {
                    System.out.println("error parsing " + s
                            + ": unsatisfiable operator " + tok);
                    return null;
                } else if (n == 1) {
                    System.out.println("error parsing " + s
                            + ": indentity operator " + tok);
                    return null;
                } else if (n > stack.size()) {
                    System.out.println("error parsing " + s
                            + ": stack underflow at " + tok);
                    return null;
                }

                /* pop n things and fill in children */
                node = baseNode(k, null);
                node.children = new FhcpabePolicy[n];

                for (i = n - 1; i >= 0; i--)
                    node.children[i] = stack.remove(stack.size() - 1);

                /* push result */
                stack.add(node);
            }
        }

        if (stack.size() > 1) {
            System.out.println("error parsing " + s
                    + ": extra node left on the stack");
            return null;
        } else if (stack.size() < 1) {
            System.out.println("error parsing " + s + ": empty policy");
            return null;
        }

        root = stack.get(0);
        root.level_num = level_num;
        return root;
    }

    private static FhcpabePolicy baseNode(int k, String s) {
        FhcpabePolicy p = new FhcpabePolicy();

        p.k = k;
        if (!(s == null))
            p.attr = s;
        else
            p.attr = null;
        p.q = null;

        return p;
    }

    private static void fillPolicy(FhcpabePolicy p, FhcpabePub pub, Element e,ArrayList<Element> cks)
            throws NoSuchAlgorithmException {

        int i;
        Element r, t, h;
        Pairing pairing = pub.p;
        r = pairing.getZr().newElement();
        t = pairing.getZr().newElement();
        h = pairing.getG1().newElement();


        p.q = randPoly(p.k - 1, e);

        if (p.children == null || p.children.length == 0) {
            p.c = pairing.getG1().newElement();
            p.cp = pairing.getG1().newElement();

            elementFromString(h, p.attr);
            p.c = pub.h.duplicate();
            p.c.powZn(p.q.coef[0]);
            p.cp = h.duplicate();
            p.cp.powZn(p.q.coef[0]);
        } else {

//            System.out.println("si="+e);
//            Element Ai = pairing.getGT().newElement();
//            Ai = pub.egg.duplicate();
//            Ai.powZn(pub.r);
//            Ai.powZn(pub.beta);
//            Ai.powZn(e);
//            System.out.println("Ai="+Ai);


            Element ck;
            ck = pairing.getGT().newElement();
            ck.setToRandom();
            cks.add(ck);

            p.c_hat = pub.g_hat_alpha.duplicate();
            p.c_hat.powZn(e);
            p.c_hat.mul(ck);

            p.cs = pub.g.duplicate();
            p.cs.powZn(e);

            for (i = 0; i < p.children.length; i++) {
                r.set(i + 1);
                evalPoly(t, p.q, r);
                fillPolicy(p.children[i], pub, t,cks);
            }
        }

    }

    private static void evalPoly(Element r, FhcpabePolynomial q, Element x) {
        int i;
        Element s, t;

        s = r.duplicate();
        t = r.duplicate();

        r.setToZero();
        t.setToOne();

        for (i = 0; i < q.deg + 1; i++) {
            /* r += q->coef[i] * t */
            s = q.coef[i].duplicate();
            s.mul(t);
            r.add(s);

            /* t *= x */
            t.mul(x);
        }

    }

    private static FhcpabePolynomial randPoly(int deg, Element zeroVal) {
        int i;
        FhcpabePolynomial q = new FhcpabePolynomial();
        q.deg = deg;
        q.coef = new Element[deg + 1];

        for (i = 0; i < deg + 1; i++)
            q.coef[i] = zeroVal.duplicate();

        q.coef[0].set(zeroVal);

        for (i = 1; i < deg + 1; i++)
            q.coef[i].setToRandom();

        return q;
    }

    private static void checkSatisfy(FhcpabePolicy p, FhcpabePrv prv) {
        int i, l;
        String prvAttr;

        p.satisfiable = false;
        if (p.children == null || p.children.length == 0) {
            for (i = 0; i < prv.comps.size(); i++) {
                prvAttr = prv.comps.get(i).attr;
                // System.out.println("prvAtt:" + prvAttr);
                // System.out.println("p.attr" + p.attr);
                if (prvAttr.compareTo(p.attr) == 0) {
                    // System.out.println("=staisfy=");
                    p.satisfiable = true;
                    p.attri = i;
                    break;
                }
            }
        } else {
            for (i = 0; i < p.children.length; i++)
                checkSatisfy(p.children[i], prv);

            l = 0;
            for (i = 0; i < p.children.length; i++)
                if (p.children[i].satisfiable)
                    l++;

            if (l >= p.k)
                p.satisfiable = true;
        }
    }

    private static void pickSatisfyMinLeaves(FhcpabePolicy p, FhcpabePrv prv) {
        int i, k, l, c_i;
        int len;
        ArrayList<Integer> c = new ArrayList<Integer>();

        if (p.children == null || p.children.length == 0)
            p.min_leaves = 1;
        else {
            len = p.children.length;
            for (i = 0; i < len; i++)
                if (p.children[i].satisfiable)
                    pickSatisfyMinLeaves(p.children[i], prv);

            for (i = 0; i < len; i++)
                c.add(new Integer(i));

            //Collections.sort(c, new IntegerComparator(p));

            p.satl = new ArrayList<Integer>();
            p.min_leaves = 0;
            l = 0;

            for (i = 0; i < len && l < p.k; i++) {
                c_i = c.get(i).intValue(); /* c[i] */
                if (p.children[c_i].satisfiable) {
                    l++;
                    p.min_leaves += p.children[c_i].min_leaves;
                    k = c_i + 1;
                    p.satl.add(new Integer(k));
                }
            }
        }
    }

    private static class IntegerComparator implements Comparator<Integer> {
        FhcpabePolicy policy;

        public IntegerComparator(FhcpabePolicy p) {
            this.policy = p;
        }

        @Override
        public int compare(Integer o1, Integer o2) {
            int k, l;

            k = policy.children[o1.intValue()].min_leaves;
            l = policy.children[o2.intValue()].min_leaves;

            return	k < l ? -1 :
                    k == l ? 0 : 1;
        }
    }

    private static void decFlatten(Element r, FhcpabePolicy p, FhcpabePrv prv,
                                   FhcpabePub pub) {
        Element one;
        one = pub.p.getZr().newElement();
        one.setToOne();
        r.setToOne();

        decNodeFlatten(r, one, p, prv, pub);
    }

    private static void decNodeFlatten(Element r, Element exp, FhcpabePolicy p,
                                       FhcpabePrv prv, FhcpabePub pub) {
        if (p.children == null || p.children.length == 0)
            decLeafFlatten(r, exp, p, prv, pub);
        else
        {
            decInternalFlatten(r, exp, p, prv, pub);
        }

    }

    private static void decLeafFlatten(Element r, Element exp, FhcpabePolicy p,
                                       FhcpabePrv prv, FhcpabePub pub) {
        FhcpabePrvComp c;
        Element s, t;

        c = prv.comps.get(p.attri);

        s = pub.p.getGT().newElement();
        t = pub.p.getGT().newElement();

        s = pub.p.pairing(p.c, c.d); /* num_pairings++; */
        t = pub.p.pairing(p.cp, c.dp); /* num_pairings++; */
        t.invert();
        s.mul(t); /* num_muls++; */
        s.powZn(exp); /* num_exps++; */

        r.mul(s); /* num_muls++; */
    }

    private static void decInternalFlatten(Element r, Element exp,
                                           FhcpabePolicy p, FhcpabePrv prv, FhcpabePub pub) {
        int i;
        Element t, expnew;

        t = pub.p.getZr().newElement();
        expnew = pub.p.getZr().newElement();

        for (i = 0; i < p.satl.size(); i++) {
            lagrangeCoef(t, p.satl, (p.satl.get(i)).intValue());
            expnew = t.duplicate();
            decNodeFlatten(r, expnew, p.children[p.satl.get(i) - 1], prv, pub);
        }

        Element ck,t2;

        ck = pub.p.getGT().newElement();
        ck = p.c_hat.duplicate();
        ck.mul(r);

        t2 = pub.p.pairing(p.cs,prv.d);
        t2.invert();
        ck.mul(t2);
        p.ck = ck;

        //System.out.println("Ai`="+r);


        r.powZn(exp);



    }

    private static void lagrangeCoef(Element r, ArrayList<Integer> s, int i) {
        int j, k;
        Element t;

        t = r.duplicate();

        r.setToOne();
        for (k = 0; k < s.size(); k++) {
            j = s.get(k).intValue();
            if (j == i)
                continue;
            t.set(-j);
            r.mul(t); /* num_muls++; */
            t.set(i - j);
            t.invert();
            r.mul(t); /* num_muls++; */
        }
    }
}
