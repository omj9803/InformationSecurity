import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class E2EEChat {
    static Random rand = new Random();

    private Socket clientSocket = null;
    BigInteger mykey;
    byte[] ivByte;

    BigInteger p = new BigInteger(Integer.toString(primeInteger(10000000)));
    BigInteger q = new BigInteger(Integer.toString(primeInteger(1000)));
    int a = rand.nextInt(5) + 2;
    BigInteger A = (q.pow(a)).mod(p);

    public Socket getSocketContext() {
        return clientSocket;
    }

    // 접속 정보, 필요시 수정
    private final String hostname = "homework.islab.work";
    private final int port = 8080;

    public E2EEChat() throws IOException {

//        System.out.println("생성 ! \n" + "p : " + p + "\nq : " + q + "\na : " + a + "\nA : " + A);

        clientSocket = new Socket();
        clientSocket.connect(new InetSocketAddress(hostname, port)); // 서버연결

        InputStream stream = clientSocket.getInputStream();

        Thread senderThread = new Thread(new MessageSender(this));
        senderThread.start();

        while (true) {
            try {
                if (clientSocket.isClosed() || !senderThread.isAlive()) {
                    break;
                }

                byte[] recvBytes = new byte[2048];
                int recvSize = stream.read(recvBytes);

                if (recvSize == 0) {
                    continue;
                }

                String recv = new String(recvBytes, 0, recvSize, StandardCharsets.UTF_8);

                parseReceiveData(recv);

            } catch (IOException | InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException ex) {
                System.out.println("소켓 데이터 수신 중 문제가 발생하였습니다.");
                break;
            }
        }

        try {
            System.out.println("입력 스레드가 종료될때까지 대기중...");
            senderThread.join();

            if (clientSocket.isConnected()) {
                clientSocket.close();
            }
        } catch (InterruptedException ex) {
            System.out.println("종료되었습니다.");
        }
    }

    public void parseReceiveData(String recvData) throws IOException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        // 여기부터 3EPROTO 패킷 처리를 개시합니다.
        System.out.println(recvData + "\n==== recv ====");
        String[] parseData = recvData.split("\n");
        if (parseData[0].split(" ")[1].equals("KEYXCHG")) {
            if (parseData[1].contains("Diffie")) {
                if (mykey != null) {
                    String reSend = "3EPROTO KEYXCHGFAIL\nAlgo: Diffie\nFrom: "
                            + parseData[3].split(":")[1].trim() + "\nTo: "
                            + parseData[2].split(":")[1].trim()
                            + "\n\nDuplicated Key Exchange Request";
                    byte[] payload = reSend.getBytes(StandardCharsets.UTF_8);
                    clientSocket.getOutputStream().write(payload, 0, payload.length);
                } else {
                    String[] args = parseData[parseData.length - 1].split("@");
                    if (args.length == 3) { // p,q,A 를 받은 상황
                        // B 계산 후 보냄
                        p = new BigInteger(args[0]);
                        q = new BigInteger(args[1]);
                        A = new BigInteger(args[2]);
                        int b = rand.nextInt(5) + 2;
                        System.out.println("\n b : " + b);
                        BigInteger B = (q.pow(b)).mod(p);
                        // 내 키 리셋해
                        String reSend = "";
                        mykey = (A.pow(b)).mod(p);
                        System.out.println("Receive p,q,A, mykey is " + mykey);
                        reSend = "3EPROTO KEYXCHGOK\nAlgo: Diffie\nFrom: "
                                + parseData[3].split(":")[1].trim() + "\nTo: "
                                + parseData[2].split(":")[1].trim() + "\n\n" + B;
                        byte[] payload = reSend.getBytes(StandardCharsets.UTF_8);
                        clientSocket.getOutputStream().write(payload, 0, payload.length);

                    } else { // B를 받은 상황
                        // 내 키만 리셋해
                        BigInteger B = new BigInteger(args[0]);
                        mykey = (B.pow(a)).mod(p);
                        System.out.println("Receive B , mykey is " + mykey);
                    }
                }

                // 바뀐 key가 중복인 경우 Fail return ..


            } else { // AES-256-CBC
                String args = parseData[parseData.length - 1];
                Base64.Decoder dec = Base64.getDecoder();
                if (ivByte != null) {
                    String reSend = "3EPROTO KEYXCHGFAIL\nFrom: "
                            + parseData[3].split(":")[1].trim()
                            + "\n\nDuplicated Key Exchange Request";
                    byte[] payload = reSend.getBytes(StandardCharsets.UTF_8);
                    clientSocket.getOutputStream().write(payload, 0, payload.length);
                } else {
                    ivByte = dec.decode(args.getBytes(StandardCharsets.UTF_8));
                }
            }
        } else if (parseData[0].contains("MSGRECV")) {
            String cipherText = parseData[5];
            String paddingResult = mykey.toString();
            int padding = 32 - paddingResult.length();
            for (int i = 0; i < padding; i++) {
                paddingResult += Integer.toString(padding);
            }
            String finalKey = paddingResult.substring(0, 32); // 32byte key padding
            String decryptedText = decryption(finalKey, cipherText);
            System.out.println(decryptedText);
        } else if (parseData[0].contains("KEYXCHGRST")) {
            if (parseData[1].contains("Diffie")) {
                String[] args = parseData[parseData.length - 1].split("@");
                if (args.length == 3) { // p,q,A 를 받은 상황
                    // B 계산 후 보내줘야돼
                    p = new BigInteger(args[0]);
                    q = new BigInteger(args[1]);
                    A = new BigInteger(args[2]);
                    int b = rand.nextInt(5) + 2;
                    System.out.println("\n b : " + b);
                    BigInteger B = (q.pow(b)).mod(p);
                    // 내 키 리셋해
                    mykey = (A.pow(b)).mod(p);
                    System.out.println("Receive p,q,A, mykey is " + mykey);
                    String reSend = "3EPROTO KEYXCHG\nAlgo: Diffie\nFrom: "
                            + parseData[3].split(":")[1].trim() + "\nTo: "
                            + parseData[2].split(":")[1].trim() + "\n\n" + B;

                    byte[] payload = reSend.getBytes(StandardCharsets.UTF_8);
                    clientSocket.getOutputStream().write(payload, 0, payload.length);

                } else { // B를 받은 상황
                    // 내 키만 리셋해
                    BigInteger B = new BigInteger(args[0]);
                    mykey = (B.pow(a)).mod(p);
                    System.out.println("Receive B , mykey is " + mykey);
                }

            } else { // AES-256-CBC
                String args = parseData[parseData.length - 1];
                Base64.Decoder dec = Base64.getDecoder();
                ivByte = dec.decode(args.getBytes(StandardCharsets.UTF_8));

            }
        } else if (parseData[0].split(" ")[1].equals("KEYXCHGOK")) {
            String[] args = parseData[parseData.length - 1].split("@");
            BigInteger B = new BigInteger(args[0]);
            mykey = (B.pow(a)).mod(p);
//            System.out.println("Receive B , mykey is " + mykey);
        }

    }

    public String decryption(String key, String cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
        byte[] IVData = ivByte;
        SecretKey secretKey = new SecretKeySpec(keyData, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IVData));
        byte[] decrypted = Base64.getDecoder().decode(cipherText.getBytes(StandardCharsets.UTF_8));
        return new String(cipher.doFinal(decrypted), StandardCharsets.UTF_8);
    }

    public int primeInteger(int range) {
        boolean isPrime = false;
        int prime = 0;
        while (!isPrime) {
            prime = rand.nextInt(range) + 1000000000; // 1000000000 ~ range + 1000000000
            boolean found = false;
            for (int i = 2; i * i <= prime; i++) {
                if (prime % i == 0) {
                    found = true;
                    break;
                }
            }
            if (!found) isPrime = true;
        }
        return prime;
    }
    // 필요한 경우 추가로 메서드를 정의하여 사용합니다.

    public static void main(String[] args) {
        try {
            new E2EEChat();
        } catch (UnknownHostException ex) {
            System.out.println("연결 실패, 호스트 정보를 확인하세요.");
        } catch (IOException ex) {
            System.out.println("소켓 통신 중 문제가 발생하였습니다.");
        }
    }
}

// 사용자 입력을 통한 메세지 전송을 위한 Sender Runnable Class
// 여기에서 메세지 전송 처리를 수행합니다.
class MessageSender implements Runnable {
    E2EEChat clientContext;
    OutputStream socketOutputStream;

    public MessageSender(E2EEChat context) throws IOException {
        clientContext = context;

        Socket clientSocket = clientContext.getSocketContext();
        socketOutputStream = clientSocket.getOutputStream();
    }

    @Override
    public void run() {
        Scanner scanner = new Scanner(System.in);
        BigInteger myKey = clientContext.mykey;
        while (true) {
            try {

                String message = scanner.nextLine().trim();
                String totalMessage = message + "\n";
                if (message.contains("CONNECT") || message.contains("DISCONNECT")) {
                    totalMessage += scanner.nextLine().trim() + "\n"; // Credential input stream.

                }
                if (message.contains("KEYXCHG") || message.contains("KEYCHGRST")) {
                    for (int i = 0; i < 3; i++) { // algo , from, to, blank input stream.
                        totalMessage += scanner.nextLine().trim() + "\n";
                    }
                    if (totalMessage.contains("Diffie")) {
                        totalMessage += "\n";
                        totalMessage += clientContext.p + "@" + clientContext.q + "@" + clientContext.A;
                    } else {
                        totalMessage += scanner.nextLine().trim() + "\n";
                        String iv = scanner.nextLine().trim();
                        Base64.Decoder dec = Base64.getDecoder();
                        clientContext.ivByte = dec.decode(iv.getBytes(StandardCharsets.UTF_8));
                        totalMessage += iv;
                    }
                }
                if (message.contains("MSGSEND")) {
                    String nonce = "";
                    for (int i = 0; i < 4; i++) { // from, to, nonce, blank input stream.
                        if (i == 2) {
                            nonce = scanner.nextLine().trim();
                            totalMessage += nonce + "\n";
                        } else {
                            totalMessage += scanner.nextLine().trim() + "\n";
                        }
                    }
                    String plainText = scanner.nextLine().trim();
                    if (clientContext.mykey == null) {
                        System.out.println("You have to exchange key first!");
                        continue;
                    }
                    String paddingResult = clientContext.mykey.toString();
                    int padding = 32 - paddingResult.length();
                    for (int i = 0; i < padding; i++) {
                        paddingResult += Integer.toString(padding);
                    }
                    String finalKey = paddingResult.substring(0, 32); // 32byte key padding
                    if (clientContext.ivByte == null) {
                        System.out.println("You have to exchange IV first!");
                        continue;
                    }
                    String enPlainText = encryption(finalKey, plainText); // encrypted plaintext
//                    System.out.println("암호화된 텍스트는 " + enPlainText);
                    totalMessage += enPlainText;
                }

                // write to outputstream.
                byte[] result = totalMessage.getBytes(StandardCharsets.UTF_8);
                socketOutputStream.write(result, 0, result.length);

            } catch (IOException ex) {
                break;
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }

        System.out.println("MessageSender runnable end");
    }

    public String encryption(String key, String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException {
        String result = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] keyData = key.getBytes(StandardCharsets.UTF_8);
            byte[] IV = clientContext.ivByte;
            SecretKey secretKey = new SecretKeySpec(keyData, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
            byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            result = new String(Base64.getEncoder().encode(encrypted));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            result = "오류!";
            e.printStackTrace();
        }
        return result;
    }
}