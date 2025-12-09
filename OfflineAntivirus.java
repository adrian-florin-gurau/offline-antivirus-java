package ro.ase.ism.sap.gurau.adrian.florin;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

enum Colors {
    RESET, RED, YELLOW, GREEN, BLUE, PURPLE
}

final class CustomPrinter {
    private final static Map<Colors, String> COLORS = new HashMap<>();

    static {
        COLORS.put(Colors.RESET, "\u001B[0m");
        COLORS.put(Colors.RED, "\u001B[31m");
        COLORS.put(Colors.YELLOW, "\u001B[33m");
        COLORS.put(Colors.GREEN, "\u001B[32m");
        COLORS.put(Colors.BLUE, "\u001B[34m");
        COLORS.put(Colors.PURPLE, "\u001B[35m");
    }

    public static void show(Colors color, String message) {
        System.out.println(COLORS.get(color) + message + COLORS.get(Colors.RESET));
    }

    private CustomPrinter() {}
}

final class Path {
    private final File file;
    private final Integer level;

    Path(File file, Integer level) {
        this.file = file;
        this.level = level;
    }

    public File getFile() {
        return file;
    }

    public Integer getLevel() {
        return level;
    }
}

final class DateUtils {
    public static String getTimestamp() {
        ZonedDateTime now = ZonedDateTime.now();
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
        return now.format(dtf);
    }

    public static String getGmtOffset() {
        ZonedDateTime now = ZonedDateTime.now();
        return now.getOffset().getId().replace(":", "");
    }

    public static String getZoneName() {
        ZonedDateTime now = ZonedDateTime.now();
        return now.getZone().getId().replace("/", "_");
    }

    public static String getFullStamp() {
        return getTimestamp() + "_GMT" + getGmtOffset() + "_" + getZoneName();
    }

    public static String buildFileName(String prefix, String extension) {
        return prefix + "_" + getFullStamp() + "." + extension;
    }

    private DateUtils() {}
}

public class OfflineAntivirus {
    private static final String SCAN_MODE = "scan";
    private static final String CHECK_MODE = "check";

    private static final int EXIT_CODE_GOOD = 0;
    private static final int EXIT_CODE_ARGUMENTS_COUNT = 1;
    private static final int EXIT_CODE_SECRET = 2;
    private static final int EXIT_CODE_MODE = 3;
    private static final int EXIT_CODE_ROOT_PATH = 4;
    private static final int EXIT_CODE_HMAC_FILE_NOT_EXISTS = 5;
    private static final int EXIT_CODE_HMAC_FILE_NOT_A_FILE = 6;
    private static final int EXIT_CODE_LEVELS_DEEP = 7;
    private static final int EXIT_CODE_HMAC_FILE_FORMAT = 8;
    private static final int EXIT_CODE_USER_INPUT = 9;

    private static Mac MAC = null;
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static void setup() throws IOException, InterruptedException {
        // Enable ANSI on Windows
        if (System.getProperty("os.name").startsWith("Windows")) {
            new ProcessBuilder("cmd", "/c", "echo").inheritIO().start().waitFor();
        }
    }

    private static void checkArguments(String[] args) {
        if (args.length != 4 && args.length != 5) {
            CustomPrinter.show(Colors.RED,"Wrong command: java OfflineAntivirus.java <" + SCAN_MODE + "|" + CHECK_MODE + "> <secret> <rootPath> <hmacFile> [<noOfLevelsDeep>]");
            System.exit(EXIT_CODE_ARGUMENTS_COUNT);
        }
    }

    private static void checkMode(String[] args) {
        if (!args[0].equals(SCAN_MODE) && !args[0].equals(CHECK_MODE)) {
            CustomPrinter.show(Colors.RED, "Wrong command: First argument must be '" + SCAN_MODE + "' or '" + CHECK_MODE + "'!");
            System.exit(EXIT_CODE_MODE);
        }
    }

    private static void checkSecret(String[] args) {
        if (args[1].length() < 8) {
            CustomPrinter.show(Colors.RED, "Wrong command: Secret should have at least 8 characters, but 32 is recommended!");
            System.exit(EXIT_CODE_SECRET);
        }
    }

    private static void checkHmacFileFormat(String[] args) {
        if (!args[3].toLowerCase().endsWith(".txt")) {
            CustomPrinter.show(Colors.RED, "Wrong command: HmacFile should be .txt!");
            System.exit(EXIT_CODE_HMAC_FILE_FORMAT);
        }
    }

    private static void checkHmacFile(String[] args) {
        checkHmacFileFormat(args);
        File file = new File(args[3]);
        if (!file.exists()) {
            CustomPrinter.show(Colors.RED, "Error: HmacFile " + args[3] + " does not exist!");
            System.exit(EXIT_CODE_HMAC_FILE_NOT_EXISTS);
        }
        if (!file.isFile()) {
            CustomPrinter.show(Colors.RED, "Error: " + args[3] + " is not a file!");
            System.exit(EXIT_CODE_HMAC_FILE_NOT_A_FILE);
        }
    }

    private static void prepareHmacFile(String[] args) {
        checkHmacFileFormat(args);
        File file = new File(args[3]);
        if (file.exists()) {
            CustomPrinter.show(Colors.PURPLE, "Warning: " + args[3] + " already exists! Overwrite? [Y/n]: ");
            Scanner scanner = new Scanner(System.in);
            if (!scanner.nextLine().equalsIgnoreCase("Y")) {
                scanner.close();
                System.exit(EXIT_CODE_USER_INPUT);
            }
            scanner.close();
        }
    }

    private static void checkLevelsDeep(String[] args) {
        if (args.length == 5 && !args[4].matches("[1-9][0-9]*")) {
            CustomPrinter.show(Colors.RED, "Wrong command: Levels deep should be a natural number above 0!");
            System.exit(EXIT_CODE_LEVELS_DEEP);
        }
    }

    private static void setupHMAC(String secret) throws InvalidKeyException, NoSuchAlgorithmException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), HMAC_ALGORITHM);
        MAC = Mac.getInstance(HMAC_ALGORITHM);
        MAC.init(secretKeySpec);
    }

    private static byte[] computeHMAC(String filePath) throws IOException {
        MAC.reset();
        try (FileInputStream fileInputStream = new FileInputStream(filePath);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream, 4096)) {
            byte[] fileBytes = new byte[4096];

            int bytesRead;
            while ((bytesRead = bufferedInputStream.read(fileBytes)) != -1) {
                MAC.update(fileBytes, 0, bytesRead);
            }
        }
        return MAC.doFinal();
    }

    private static String toBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static Map<String, String> readHmacFile(BufferedReader br, String hmacFilePath) throws IOException {
        Map<String, String> map = new HashMap<>();
        if (br != null) {
            String path, hmac;
            while ((path = br.readLine()) != null && (hmac = br.readLine()) != null) {
                map.put(path, hmac);
            }
            map.remove(hmacFilePath);
        }
        return map;
    }

    private static void traverseRootPath(Queue<Path> queue, int deep, BufferedReader br, BufferedWriter bw, String hmacFilePath) throws IOException {
        if (queue.isEmpty()) {
            return;
        }
        Map<String, String> storedHmacs = readHmacFile(br, hmacFilePath);
        File reportFile = null;
        FileWriter fileWriterReport = null;
        BufferedWriter bufferedWriterReport = null;
        if (br != null) {
            reportFile = new File(DateUtils.buildFileName("report", "txt"));
            if (!reportFile.exists()) {
                reportFile.createNewFile();
            }
            fileWriterReport = new FileWriter(reportFile);
            bufferedWriterReport = new BufferedWriter(fileWriterReport);
        }
        int noOfOkayFiles = 0;
        int noOfCorruptedFiles = 0;
        int noOfNewFiles = 0;
        do {
            Path parent = queue.poll();
            if (parent != null && parent.getFile().canRead()) {
                if (parent.getFile().isDirectory()) {
                    if (deep == 0 || parent.getLevel() < deep - 1) {
                        String[] children = parent.getFile().list();
                        if (children != null) {
                            for (String child : children) {
                                File childFile = new File(parent.getFile(), child);
                                if (childFile.canRead()) {
                                    Integer childLevel = parent.getLevel() + 1;
                                    queue.add(new Path(childFile, childLevel));
                                }
                            }
                        }
                    }
                }
                else if (parent.getFile().isFile()) {
                    String hmac = toBase64(computeHMAC(parent.getFile().getAbsolutePath()));
                    if (br != null) {
                        String foundHmac = storedHmacs.get(parent.getFile().getAbsolutePath());
                        if (foundHmac != null) {
                            if (hmac.equals(foundHmac)) {
                                noOfOkayFiles++;
                                CustomPrinter.show(Colors.GREEN, "[OK] " + parent.getFile().getAbsolutePath());
                                bufferedWriterReport.write("[OK]," + parent.getFile().getAbsolutePath() + "," + hmac + "\n");
                            } else {
                                noOfCorruptedFiles++;
                                CustomPrinter.show(Colors.YELLOW, "[CORRUPTED] " + parent.getFile().getAbsolutePath());
                                bufferedWriterReport.write("[CORRUPTED]," + parent.getFile().getAbsolutePath() + "," + hmac + "\n");
                            }
                        } else {
                            noOfNewFiles++;
                            CustomPrinter.show(Colors.BLUE, "[NEW] " + parent.getFile().getAbsolutePath());
                            bufferedWriterReport.write("[NEW]," + parent.getFile().getAbsolutePath() + "," + hmac + "\n");
                        }
                    } else if (bw != null) {
                        bw.write(parent.getFile().getAbsolutePath());
                        bw.newLine();
                        bw.write(hmac);
                        bw.newLine();
                        CustomPrinter.show(Colors.GREEN, parent.getFile().getAbsolutePath());
                    }
                }
            }
        } while (!queue.isEmpty());
        if (br != null) {
            CustomPrinter.show(Colors.PURPLE, "\nNumber of files: " + (noOfOkayFiles + noOfCorruptedFiles + noOfNewFiles) + " | OK: " + noOfOkayFiles + " | CORRUPTED: " +  noOfCorruptedFiles + " | NEW: " + noOfNewFiles);
            CustomPrinter.show(Colors.PURPLE, "INFO: The HMAC file is always counted as a NEW file!");
            CustomPrinter.show(Colors.PURPLE, "Report file: " + reportFile.getAbsolutePath());
            bufferedWriterReport.close();
        } else if (bw != null) {
            CustomPrinter.show(Colors.PURPLE, "\nHMAC file updated: " + hmacFilePath);
        }
    }

    private static void prepareTraverseRootPath(String[] args) throws IOException {
        File rootFile = new File(args[2]);
        if (!rootFile.exists()) {
            CustomPrinter.show(Colors.RED, "Error: Root path " + args[2] + " does not exist!");
            System.exit(EXIT_CODE_ROOT_PATH);
        }
        int deep = 0;
        if (args.length == 5) {
            deep = Integer.parseInt(args[4]);
        }
        File hmacFile = new File(args[3]);
        if (args[0].equals(SCAN_MODE) && !hmacFile.exists()) {
            hmacFile.createNewFile();
        }
        FileReader hmacFileReader = null;
        FileWriter hmacFileWriter = null;
        BufferedReader hmacBufferedReader = null;
        BufferedWriter hmacBufferedWriter = null;
        if (args[0].equals(SCAN_MODE)) {
            hmacFileWriter = new FileWriter(hmacFile);
            hmacBufferedWriter = new BufferedWriter(hmacFileWriter);
        } else {
            hmacFileReader = new FileReader(hmacFile);
            hmacBufferedReader = new BufferedReader(hmacFileReader);
        }
        boolean readyToRead = false;
        boolean readyToWrite = false;
        if (hmacBufferedReader != null) {
            readyToRead = true;
        } else {
            readyToWrite = true;
        }

        Queue<Path> queue = new LinkedList<>();
        queue.add(new Path(rootFile, 0));

        traverseRootPath(queue, deep, hmacBufferedReader, hmacBufferedWriter, args[3]);

        if (readyToRead) {
            hmacBufferedReader.close();
        }
        if (readyToWrite) {
            hmacBufferedWriter.close();
        }
    }

    private static void beginScan(String[] args) throws IOException {
        prepareHmacFile(args);
        CustomPrinter.show(Colors.PURPLE, "Beginning " + SCAN_MODE + " on " + args[2] + "\n");
        prepareTraverseRootPath(args);
    }

    private static void beginCheck(String[] args) throws IOException {
        checkHmacFile(args);
        CustomPrinter.show(Colors.PURPLE, "Beginning " + CHECK_MODE + " on " + args[2] + "\n");
        prepareTraverseRootPath(args);
    }

    private static void run(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        checkArguments(args);
        checkMode(args);
        checkSecret(args);
        checkLevelsDeep(args);
        setupHMAC(args[1]);
        if (args[0].equals(SCAN_MODE)) {
            beginScan(args);
        } else {
            beginCheck(args);
        }
    }

    public static void main(String[] args) throws IOException, InterruptedException, NoSuchAlgorithmException, InvalidKeyException {
        setup();
        System.out.println();
        run(args);
        System.exit(EXIT_CODE_GOOD);
    }
}