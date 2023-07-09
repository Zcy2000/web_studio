import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class CPABE {

    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();

        Element g_alpha = g.powZn(alpha).getImmutable();
        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = bp.pairing(g,g).powZn(alpha).getImmutable();

        Properties mskProp = new Properties();
        mskProp.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));

        Properties pkProp = new Properties();
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("g_beta", Base64.getEncoder().withoutPadding().encodeToString(g_beta.toBytes()));
        pkProp.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String g_alphaString = mskProp.getProperty("g_alpha");
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_alphaString)).getImmutable();

        Properties skProp = new Properties();

        Element t = bp.getZr().newRandomElement().getImmutable();
        Element D = g_alpha.mul(g_beta.powZn(t)).getImmutable();
        Element D0 = g.powZn(t);

        skProp.setProperty("D", Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
        skProp.setProperty("D0", Base64.getEncoder().withoutPadding().encodeToString(D0.toBytes()));

        for (int att : userAttList) {
            byte[] idHash = sha1(Integer.toString(att));
            Element H = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();
            Element Datt = H.powZn(t).getImmutable();
            skProp.setProperty("D"+att, Base64.getEncoder().withoutPadding().encodeToString(Datt.toBytes()));
        }

        skProp.setProperty("userAttList", Arrays.toString(userAttList));
        storePropToFile(skProp, skFileName);
    }

    public static void encrypt(String pairingParametersFileName, Element message, Node[] accessTree,
                               String pkFileName, String ctFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String g_betaString = pkProp.getProperty("g_beta");
        Element g_beta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_betaString)).getImmutable();
        String egg_alphaString = pkProp.getProperty("egg_alpha");
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(egg_alphaString)).getImmutable();

        Properties ctProp = new Properties();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element C = message.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element C0 = g.powZn(s).getImmutable();

        ctProp.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        ctProp.setProperty("C0", Base64.getEncoder().withoutPadding().encodeToString(C0.toBytes()));


        accessTree[0].secretShare = s;
        nodeShare(accessTree, accessTree[0], bp);

        for (Node node:accessTree) {
            if (node.isLeaf()){
                Element r = bp.getZr().newRandomElement().getImmutable();

                byte[] idHash = sha1(Integer.toString(node.att));
                Element Hi = bp.getG1().newElementFromHash(idHash, 0, idHash.length).getImmutable();

                Element C1 = g_beta.powZn(node.secretShare).mul(Hi.powZn(r.negate()));
                Element C2 = g.powZn(r);

                ctProp.setProperty("C1-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(C1.toBytes()));
                ctProp.setProperty("C2-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(C2.toBytes()));
            }
        }
        storePropToFile(ctProp, ctFileName);
    }

    public static Element Decrypt(String pairingParametersFileName, Node[] accessTree, String ctFileName, String skFileName) {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties ctProp = loadPropFromFile(ctFileName);

        Properties skProp = loadPropFromFile(skFileName);
        String userAttListString = skProp.getProperty("userAttList");
        int[] userAttList = Arrays.stream(userAttListString.substring(1, userAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();

        System.out.println("List of user properties：" + userAttListString);

        String CString = ctProp.getProperty("C");
        Element C = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(CString)).getImmutable();
        String C0String = ctProp.getProperty("C0");
        Element C0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C0String)).getImmutable();

        String DString = skProp.getProperty("D");
        Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
        String D0String = skProp.getProperty("D0");
        Element D0 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(D0String)).getImmutable();

        for (Node node : accessTree) {
            if (node.isLeaf()) {
                if (Arrays.stream(userAttList).boxed().collect(Collectors.toList()).contains(node.att)){
                    String C1tring = ctProp.getProperty("C1-"+node.att);
                    Element C1 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C1tring)).getImmutable();
                    String C2tring = ctProp.getProperty("C2-"+node.att);
                    Element C2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C2tring)).getImmutable();

                    String DattString = skProp.getProperty("D"+node.att);
                    Element Datt = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DattString)).getImmutable();

                    node.secretShare = bp.pairing(C1,D0).mul(bp.pairing(C2,Datt)).getImmutable();
                }
            }
        }
        boolean treeOK = nodeRecover(accessTree, accessTree[0], userAttList, bp);
        if (treeOK) {
            Element egg_alphas = bp.pairing(C0,D).div(accessTree[0].secretShare);
            return C.div(egg_alphas);
        }
        else {
            System.out.println("The access tree is not satisfied.");
            return null;
        }
    }

    public static Element[] randomP(int d, Element s, Pairing bp) {
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return  coef;
    }
    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].getImmutable();
        for (int i = 1; i < coef.length; i++){
            Element exp = bp.getZr().newElement(i).getImmutable();
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }
    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
    }

    public static void nodeShare(Node[] nodes, Node n, Pairing bp){
        if (!n.isLeaf()){
            Element[] coef = randomP(n.gate[0], n.secretShare, bp);
            for (int j=0; j<n.children.length; j++ ){
                Node childNode = nodes[n.children[j]];
                childNode.secretShare = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    // recover 
    public static boolean nodeRecover(Node[] nodes, Node n,  int[] atts, Pairing bp) {
        if (!n.isLeaf()) {
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            for (int j=0; j<n.children.length; j++){
                Node childNode = nodes[n.children[j]];
                if (nodeRecover(nodes, childNode, atts, bp)){
                    System.out.println("The node with index " + n.children[j] + " is sarisfied!");
                    validChildrenList.add(valueOf(n.children[j]));
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
                else {
                    System.out.println("The node with index " + n.children[j] + " is not sarisfied!");
                }
            }
            if (validChildrenList.size() == n.gate[0]){
                validChildren = validChildrenList.stream().mapToInt(i->i).toArray();
                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int i : validChildren) {
                    Element delta = lagrange(i, validChildren, 0, bp); 
                    secret = secret.mul(nodes[i].secretShare.duplicate().powZn(delta));
                }
                n.secretShare = secret;
            }
        }
        else {

            if (Arrays.stream(atts).boxed().collect(Collectors.toList()).contains(n.att)){
                n.valid = true;
            }
        }
        return n.valid;
    }

    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void basicTest() throws Exception {
        int[] userAttList = {1, 2, 3,};

        Node[] accessTree = new Node[5];
        accessTree[0] = new Node(new int[]{4,4}, new int[]{1,2,3,4});
        accessTree[1] = new Node(1);
        accessTree[2] = new Node(2);
        accessTree[3] = new Node(3);
        accessTree[4] = new Node(4);

        String dir = "data/";
        String pairingParametersFileName = "a.properties";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParametersFileName, pkFileName, mskFileName);
        keygen(pairingParametersFileName, userAttList, pkFileName, mskFileName, skFileName);

           Element message = PairingFactory.getPairing(pairingParametersFileName).getGT().newRandomElement().getImmutable();
        System.out.println("plaintext message:" + message);
        encrypt(pairingParametersFileName, message, accessTree, pkFileName, ctFileName);

       Element res = Decrypt(pairingParametersFileName, accessTree, ctFileName, skFileName);
        System.out.println("decryption result:" + res);

        if (message.isEqual(res)) {
            System.out.println("successfully decrypted!");
        }
    }
    //        Node[] accessTree = new Node[7];
//        accessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3});
//        accessTree[1] = new Node(1);
//        accessTree[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
//        accessTree[3] = new Node(5);
//        accessTree[4] = new Node(2);
//        accessTree[5] = new Node(3);
//        accessTree[6] = new Node(4);

    public static void main(String[] args) throws Exception {
        basicTest();
    }

}
