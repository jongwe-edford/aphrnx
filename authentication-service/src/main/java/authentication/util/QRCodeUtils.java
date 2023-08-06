package security.auth.util;

import java.util.UUID;

public class QRCodeUtils {
    public static final String QRCODE_NAME = UUID.randomUUID().toString();
 public static final    String pathName = QRCODE_NAME + "_";
 public static final    String filePath = "./src/main/resources/" + pathName;
}
