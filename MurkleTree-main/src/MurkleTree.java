import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class MurkleTree {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        for (int i = 0; i < 3; i++) {
            String input = scanner.nextLine();
            String[] inputToArray = input.split(" ");
            System.out.println(calculateMurkleRoot(inputToArray));
        }
        for (int i = 0; i < 3; i++) {
            String input = scanner.nextLine();
            String[] inputToArray = input.split(" ");
            String murkleRoot = inputToArray[0];
            String[] data = new String[8];
            for (int j = 0; j < 8; j++) {
                data[j] = inputToArray[j + 1];
            }
            if (murkleRoot.equals(calculateMurkleRoot(data)))
                System.out.println("Y");
            else
                System.out.println("N");
        }
        for (int i = 0; i < 3; i++) {
            String input = scanner.nextLine();
            String[] inputToArray = input.split(" ");
            String murkleRoot = inputToArray[0];
            String data = sha256(inputToArray[1]);
            String result1 = "", result2 = "", result = "";
            if (inputToArray[2].equals("R")) {
                result1 = sha256(data + inputToArray[3]);
            } else {
                result1 = sha256(inputToArray[3] + data);
            }
            if (inputToArray[4].equals("R")) {
                result2 = sha256(result1 + inputToArray[5]);
            } else {
                result2 = sha256(inputToArray[5] + result1);
            }
            if (inputToArray[6].equals("R")) {
                result = sha256(result2 + inputToArray[7]);
            } else {
                result = sha256(inputToArray[7] + result2);
            }
            if (murkleRoot.equals(result))
                System.out.println("Y");
            else
                System.out.println("N");
        }
    }

    public static String calculateMurkleRoot(String[] input) throws NoSuchAlgorithmException {
        String[] hashString = new String[8];
        for (int i = 0; i < 8; i++) {
            hashString[i] = sha256(input[i]);
        }
        String result1 = sha256(sha256(hashString[0] + hashString[1]) + sha256(hashString[2] + hashString[3]));
        String result2 = sha256(sha256(hashString[4] + hashString[5]) + sha256(hashString[6] + hashString[7]));
        String result = sha256(result1 + result2);
        return result;
    }

    public static String sha256(String msg) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(msg.getBytes());

        return bytesToHex(md.digest());
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }


}
