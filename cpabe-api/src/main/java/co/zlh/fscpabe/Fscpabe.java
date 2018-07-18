package co.zlh.fscpabe;
import co.zlh.fscpabe.access.AccessControlParameter;
import co.zlh.fscpabe.access.UnsatisfiedAccessControlException;
import co.zlh.fscpabe.access.lsss.LSSSPolicyEngine;
import co.zlh.fscpabe.access.lsss.LSSSPolicyParameter;
import co.zlh.fscpabe.access.lsss.lw10.LSSSLW10Engine;
import co.zlh.fscpabe.access.parser.ParserUtils;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.Map;

public class Fscpabe {
    private static String curveParams = "type a\n"
            + "q 87807107996633125224377819847540498158068831994142082"
            + "1102865339926647563088022295707862517942266222142315585"
            + "8769582317459277713367317481324925129998224791\n"
            + "h 12016012264891146079388821366740534204802954401251311"
            + "822919615131047207289359704531102844802183906537786776\n"
            + "r 730750818665451621361119245571504901405976559617\n"
            + "exp2 159\n" + "exp1 107\n" + "sign1 1\n" + "sign0 1\n";

    private static LSSSPolicyEngine  lsssPolicyEngine = LSSSLW10Engine.getInstance();

    public static void setup(FscpabePub pub,FscpabeMsk msk,String[] attrs)
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
        pub.h = new ArrayList<FscpabeH>();
        for(int i = 0;i<attrs.length;i++)
        {
            FscpabeH hi = new FscpabeH();
            hi.attr = attrs[i];
            hi.value = pairing.getG1().newElement();
            hi.value.setToRandom();
            pub.h.add(hi);
        }
    }

    public static FscpabePrv keygen(FscpabePub pub,FscpabeMsk msk,String[] attrs)
    {
        FscpabePrv prv = new FscpabePrv();
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
        prv.Kxs = new ArrayList<FscpabePrvKx>();
        for(int i=0;i<pub.h.size();i++)
        {
            FscpabeH hi = pub.h.get(i);
            String attri = hi.attr;
            for(int j=0;j<attrs.length;j++)
            {
                if(attrs[j].equals(attri))
                {
                    FscpabePrvKx Kx = new FscpabePrvKx();
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

    public static FscpabeCphKey enc(FscpabePub pub,String accessPolicyString)
    {
        Pairing pairing = pub.p;
        FscpabeCphKey cphKey = new FscpabeCphKey();
        FscpabeCph cph = new FscpabeCph();
        try{
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            AccessControlParameter accessControlParameter = lsssPolicyEngine.generateAccessControl(accessPolicy, rhos);
            cph.accessControlParameter = accessControlParameter;
            int secretNum = lsssPolicyEngine.getRow(accessControlParameter);
            Element[] V = new Element[secretNum];
            for(int i = 0 ;i<secretNum;i++)
            {
                Element secret = pairing.getZr().newRandomElement().getImmutable();
                V[i] = secret.duplicate().getImmutable();
            }

            cph.C = new Element[secretNum];
            cph.Cp = new Element[secretNum];
            cphKey.key = new Element[secretNum];
            for(int i = 0 ;i<secretNum;i++)
            {
                Element m = pairing.getGT().newRandomElement().getImmutable();
                cphKey.key[i] = pairing.getZr().newElement();
                cph.C[i] = pairing.getGT().newElement();
                cph.Cp[i] = pairing.getG1().newElement();

                cphKey.key[i] = m.duplicate();
                cph.C[i] = pub.egg_alpha.duplicate();
                cph.C[i].powZn(V[i]);
                cph.C[i].mul(m);
                cph.Cp[i] = pub.g.duplicate();
                cph.Cp[i].powZn(V[i]);
            }

            Map<String, Element> lambdaElementsMap = lsssPolicyEngine.secretSharing(pairing, V, accessControlParameter);
            cph.CDs = new ArrayList<FscpabeCphCD>();
            for (String key:lambdaElementsMap.keySet()
                    ) {
                FscpabeCphCD CD = new FscpabeCphCD();
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

    public static Element[] dec(FscpabePub pub,FscpabeCph cph,FscpabePrv prv)
    {
        Pairing pairing = pub.p;
        int secretNum= cph.C.length;
        Element[] ms = new Element[secretNum];
        for(int j=0;j<secretNum;j++)
        {
            Element m,e_cp_k,denominator,F;
            m = pairing.getGT().newElement();
            e_cp_k = pairing.getGT().newElement();
            denominator = pairing.getGT().newElement();
            F = pairing.getGT().newElement();
            AccessControlParameter accessControlParameter = cph.accessControlParameter;
            String[] attributeSet = getAttrs(prv.Kxs);

            try {
                Map<String, Element> omegaElementsMap = lsssPolicyEngine.reconstructOmegas(pairing, attributeSet, accessControlParameter,j);
                int zeroNum = 0;
                for (String key:omegaElementsMap.keySet()
                        ) {
                    if(omegaElementsMap.get(key).isZero())
                        zeroNum++;
                }
                if(zeroNum == omegaElementsMap.size())
                {
                    ms[j] = null;
                    continue;
                }
                e_cp_k = pairing.pairing(cph.Cp[j],prv.K);
                denominator = getDenominator(pairing,prv,cph,omegaElementsMap);
                //System.out.println("denominator = " + denominator);
                denominator.invert();
                F = e_cp_k.duplicate();
                F.mul(denominator);
                F.invert();
                m = cph.C[j].duplicate();
                m.mul(F);
            }
            catch (UnsatisfiedAccessControlException e){
                System.out.println("Error for getting Exceptions...");
                e.printStackTrace();
                System.exit(0);
            }
            ms[j] = m.duplicate().getImmutable();
        }
        return ms;
    }

    public static String[] getAttrs(ArrayList<FscpabePrvKx> Kxs)
    {
        String[] attrs = new String[Kxs.size()];
        for(int i = 0;i<Kxs.size();i++)
        {
            attrs[i] = Kxs.get(i).attr;
        }
        return attrs;
    }

    public static Element getDenominator(Pairing pairing,FscpabePrv prv,FscpabeCph cph,Map<String, Element> omegaElementsMap)
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
