const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const eccrypto = require("eccrypto");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json());

let globalPublic = "";
let gloablPrivate = "";
let globalEncrypted = "";

const encrypt = (pubKey, message) => {
  return eccrypto.encrypt(pubKey, message);
};

const decrypt = (privkey, encMess) => {
  return eccrypto.decrypt(privkey, encMess);
};

app.post("/enc", async (req, res) => {
  try {
    const requestData = req.body;
    const encryptedMessage = await encrypt(
      globalPublic,
      Buffer.from(requestData.message)
    );
    globalEncrypted = encryptedMessage;
    const text = new TextDecoder().decode(encryptedMessage.ciphertext);

    res.send({
      encrypted: encryptedMessage,
      encryptedHex: encryptedMessage.ciphertext.toString("hex"),
      encryptedBuffer: encryptedMessage.ciphertext,
      encryptedText: text,
    });
  } catch (error) {
    res.sendStatus(400);
  }
});

app.post("/decr", async (req, res) => {
  try {
    const requestData = req.body;
    if (requestData.message === globalEncrypted.ciphertext.toString("hex")) {
      const decryptedBuffer = await decrypt(gloablPrivate, globalEncrypted);
      const decryptedMesasge = new TextDecoder().decode(
        Buffer.from(decryptedBuffer)
      );
      res.send({
        decryptedMesasge,
      });
    } else
      res.send({
        decryptedMesasge: "ERROR",
      });
  } catch (error) {
    res.sendStatus(400);
  }
});

app.post("/keys", async (req, res) => {
  gloablPrivate = eccrypto.generatePrivate();
  globalPublic = eccrypto.getPublic(gloablPrivate);

  res.send({
    pubKey: globalPublic.toString("hex"),
    privKey: gloablPrivate.toString("hex"),
  });
});

// Start the server
const port = process.env.PORT || 3001;
app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
