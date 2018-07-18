package co.zlh.lscpabe;
import co.zlh.lscpabe.access.AccessControlParameter;
import co.zlh.lscpabe.access.UnsatisfiedAccessControlException;
import co.zlh.lscpabe.access.lsss.LSSSPolicyEngine;
import co.zlh.lscpabe.access.lsss.lw10.LSSSLW10Engine;
import co.zlh.lscpabe.access.parser.ParserUtils;
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
import java.util.Map;

public class Lscpabe {
    private static String curveParams = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

    private static LSSSPolicyEngine  lsssPolicyEngine = LSSSLW10Engine.getInstance();

    public static void setup(LscpabePub pub,LscpabeMsk msk,String[] attrs)
    {
        Element alpha,a;

        CurveParameters params = new DefaultCurveParameters()
                .load(new ByteArrayInputStream(curveParams.getBytes()));

        pub.pairingDesc = curveParams;
        pub.p = PairingFactory.getPairing(params);
        Pairing pairing = pub.p;

        pub.g = pairing.getG1().newElement();
        alpha = pairing.getZr().newElement();
        a = pairing.getZr().newElement();
        pub.egg_alpha = pairing.getGT().newElement();
        pub.g_a = pairing.getG1().newElement();
        msk.g_alpha = pairing.getG1().newElement();

        pub.g.setToRandom();
        a.setToRandom();
        alpha.setToRandom();

        msk.g_alpha = pub.g.duplicate();
        msk.g_alpha.powZn(alpha);
        pub.egg_alpha = pairing.pairing(pub.g,msk.g_alpha);
        pub.g_a = pub.g.duplicate();
        pub.g_a.powZn(a);
        pub.h = new ArrayList<LscpabeH>();
        for(int i = 0;i<attrs.length;i++)
        {
            LscpabeH hi = new LscpabeH();
            hi.attr = attrs[i];
            hi.value = pairing.getG1().newElement();
            hi.value.setToRandom();
            pub.h.add(hi);
        }
    }

    public static LscpabePrv keygen(LscpabePub pub,LscpabeMsk msk,String[] attrs)
    {
        LscpabePrv prv = new LscpabePrv();
        Element t;
        Pairing pairing;
        pairing = pub.p;
        t = pairing.getZr().newElement();
        prv.K = pairing.getG1().newElement();
        prv.L = pairing.getG1().newElement();

        t.setToRandom();
        prv.K = pub.g_a.duplicate();
        prv.K.powZn(t);
        prv.K.mul(msk.g_alpha);
        prv.L = pub.g.duplicate();
        prv.L.powZn(t);
        prv.Kxs = new ArrayList<LscpabePrvKx>();
        for(int i=0;i<pub.h.size();i++)
        {
            LscpabeH hi = pub.h.get(i);
            String attri = hi.attr;
            for(int j=0;j<attrs.length;j++)
            {
                if(attrs[j].equals(attri))
                {
                    LscpabePrvKx Kx = new LscpabePrvKx();
                    Kx.attr = hi.attr;
                    Kx.value = pairing.getG1().newElement();
                    Kx.value = hi.value.duplicate();
                    Kx.value.powZn(t);
                    prv.Kxs.add(Kx);
                }
            }
        }
        return prv;
    }

    public static LscpabeCphKey enc(LscpabePub pub,String accessPolicyString)
    {
        Pairing pairing = pub.p;
        Element m;
        LscpabeCphKey cphKey = new LscpabeCphKey();
        LscpabeCph cph = new LscpabeCph();

        m = pairing.getGT().newRandomElement().getImmutable();
        System.out.println("m = " + m);
        cphKey.key = m;
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
//            for (int i = 0; i < accessPolicy.length; i++) {
//                for (int j = 0 ; j < accessPolicy[i].length; j++) {
//                    System.out.print(accessPolicy[i][j] + ", ");
//                }
//                System.out.println();
//            }
//            System.out.println();
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            AccessControlParameter accessControlParameter = lsssPolicyEngine.generateAccessControl(accessPolicy, rhos);
            cph.accessControlParameter = accessControlParameter;
            Element secret = pairing.getZr().newRandomElement().getImmutable();
            System.out.println("Generated Secret s = " + secret);

            cph.C = pairing.getGT().newElement();
            cph.Cp = pairing.getG1().newElement();

            cph.C = pub.egg_alpha.duplicate();
            cph.C.powZn(secret);
            cph.C.mul(m);
            cph.Cp = pub.g.duplicate();
            cph.Cp.powZn(secret);

            Map<String, Element> lambdaElementsMap = lsssPolicyEngine.secretSharing(pairing, secret, accessControlParameter);
            cph.CDs = new ArrayList<LscpabeCphCD>();
            for (String key:lambdaElementsMap.keySet()
                 ) {
                LscpabeCphCD CD = new LscpabeCphCD();
                CD.attr = key;
                Element lambda = lambdaElementsMap.get(key);
                Element h = pairing.getG1().newElement();
                for(int i = 0;i<pub.h.size();i++)
                {
                    if(key.equals(pub.h.get(i).attr))
                    {
                        h = pub.h.get(i).value;
                    }
                }
                Element h_neg_ri, ri, Ci,Di;
                ri = pairing.getZr().newRandomElement().getImmutable();
                h_neg_ri = pairing.getG1().newElement();
                Ci = pairing.getG1().newElement();
                Di = pairing.getG1().newElement();

                Di = pub.g.duplicate();
                Di.powZn(ri);
                h_neg_ri = h.duplicate();
                ri = ri.negate();
                h_neg_ri.powZn(ri);
                Ci = pub.g_a.duplicate();
                Ci.powZn(lambda);
                Ci.mul(h_neg_ri);
                CD.Ci = Ci;
                CD.Di = Di;

                cph.CDs.add(CD);
            }
            cphKey.cph = cph;
        }
        catch (Exception e){
            System.out.println(e);
        }
        return cphKey;
    }

    public static Element dec(LscpabePub pub, LscpabeCph cph,LscpabePrv prv)
    {
        Pairing pairing = pub.p;
        Element m,e_cp_k,denominator,F;
        m = pairing.getGT().newElement();
        e_cp_k = pairing.getGT().newElement();
        denominator = pairing.getGT().newElement();
        F = pairing.getGT().newElement();

        AccessControlParameter accessControlParameter = cph.accessControlParameter;
        String[] attributeSet = getAttrs(prv.Kxs);
        try {
            Map<String, Element> omegaElementsMap = lsssPolicyEngine.reconstructOmegas(pairing, attributeSet, accessControlParameter);
            e_cp_k = pairing.pairing(cph.Cp,prv.K);
            denominator = getDenominator(pairing,prv,cph,omegaElementsMap);
            System.out.println("denominator = " + denominator);
            denominator.invert();
            F = e_cp_k.duplicate();
            F.mul(denominator);
            F.invert();
            m = cph.C.duplicate();
            m.mul(F);
        }
        catch (UnsatisfiedAccessControlException e){
            System.out.println("Error for getting Exceptions...");
            e.printStackTrace();
            System.exit(0);
        }
        return m;
    }

    public static String[] getAttrs(ArrayList<LscpabePrvKx> Kxs)
    {
        String[] attrs = new String[Kxs.size()];
        for(int i = 0;i<Kxs.size();i++)
        {
            attrs[i] = Kxs.get(i).attr;
        }
        return attrs;
    }
    public static Element getDenominator(Pairing pairing,LscpabePrv prv,LscpabeCph cph,Map<String, Element> omegaElementsMap)
    {
        Element denominator;
        denominator = pairing.getGT().newElement();
        denominator.setToOne();
        for (String key:omegaElementsMap.keySet()
                ) {
            Element cldko,ecl,edk,omega,c,l,d,k;
            cldko = pairing.getGT().newElement();
            ecl = pairing.getGT().newElement();
            edk = pairing.getGT().newElement();
            omega = pairing.getG1().newElement();
            c = pairing.getG1().newElement();
            l = pairing.getG1().newElement();
            d = pairing.getG1().newElement();
            k = pairing.getG1().newElement();

            for(int i = 0;i<cph.CDs.size();i++)
            {
                if(key.equals(cph.CDs.get(i).attr))
                {
                    c = cph.CDs.get(i).Ci;
                }
            }

            l = prv.L.duplicate();

            for(int i = 0;i<cph.CDs.size();i++)
            {
                if(key.equals(cph.CDs.get(i).attr))
                {
                    d = cph.CDs.get(i).Di;
                }
            }
            for(int i = 0 ; i<prv.Kxs.size();i++)
            {
                if(key.equals(prv.Kxs.get(i).attr))
                {
                    k = prv.Kxs.get(i).value;
                }
            }
            omega = omegaElementsMap.get(key);

            ecl = pairing.pairing(c,l);
            edk = pairing.pairing(d,k);
            cldko = ecl.duplicate();
            cldko.mul(edk);
            cldko.powZn(omega);
            denominator.mul(cldko);
        }
        return denominator;
    }





}
