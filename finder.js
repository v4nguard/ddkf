// const SEARCH_STRING = "GSFARM35011";
const SEARCH_STRING = [
  0xff, 0x9f, 0x4c, 0x6b, 0xa7, 0x07, 0x0d, 0xf8, 0x90, 0x89, 0x90, 0xfa, 0xc9,
  0xcd, 0xd0, 0x8c,
];
const STRING_OFFSET = 0x01b95150;
const CIPHERCONTEXT_ADDR = 0x01b951b0;

const CIPHERCONTEXT_ADDR_RELATIVE = CIPHERCONTEXT_ADDR - STRING_OFFSET;

const SEARCH_CHUNK_SIZE = 0x10000;

function findCipherContext(reader, baseStringAddr) {
  var reader = new FileReader();
  reader.seek(baseStringAddr + CIPHERCONTEXT_ADDR_RELATIVE);

  var cipherContext = reader.read(92);
}

function findStringInBlock(block, searchString) {
  for (var i = 0; i < block.length - searchString.length; i++) {
    for (var j = 0; j < searchString.length; j++) {
      let byte1 = block[i + j];
      let byte2 = searchString[j];
      // let byte2 = searchString.charCodeAt(j);
      if (byte1 != byte2) {
        break;
      }

      if (j === searchString.length - 1) {
        return i;
      }
    }
  }

  return -1;
}

function findTreasureKeys(file, callback) {
  var offset = 0;
  var fileSize = file.size;

  var reader = new FileReader();
  reader.onload = function (e) {
    var data = new Uint8Array(e.target.result);

    let findRes = findStringInBlock(data, SEARCH_STRING.slice(0, 10));
    if (findRes !== -1) {
      console.log("Found treasure keys at offset: " + (offset + findRes));
      let cipherContextAddr = offset + findRes + CIPHERCONTEXT_ADDR_RELATIVE;
      readCipherContext(cipherContextAddr);
      return;
    }

    offset += SEARCH_CHUNK_SIZE;
    if (offset >= fileSize) {
      callback(-1);
      return;
    }

    readBlock(offset);
  };

  function readBlock(offset) {
    reader.readAsArrayBuffer(file.slice(offset, offset + SEARCH_CHUNK_SIZE));
  }

  function readCipherContext(offset) {
    var reader = new FileReader();
    reader.onload = function (e) {
      let keyData = new Uint8Array(e.target.result);
      callback(offset, keyData);
    };

    reader.readAsArrayBuffer(file.slice(offset, offset + 76));
    return;
  }

  readBlock(offset);
}

function setResultBox(type, text, isCode) {
  var resultBox = document.getElementById("result");
  resultBox.classList = "alert alert-" + type;
  if (isCode) {
    resultBox.classList += " font-monospace";
  }

  resultBox.style.display = "block";
  resultBox.innerText = text;
}

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function decodeCipherContext(data) {
  var resultText = "";

  var dv = new DataView(data.buffer);
  let unk1 = dv.getUint32(0, false);
  let cipher = dv.getUint32(4, false);
  let keylen = dv.getUint32(8, false);
  let key = data.slice(12, 12 + keylen);

  let hmac_key = data.slice(0x24, 0x24 + 16);

  resultText += "cbc_unk1:   " + unk1 + "\n";
  resultText += "cbc_cipher: " + cipher + "\n";
  resultText += "cbc_keylen: " + keylen + "\n";
  resultText += "cbc_key:    " + toHexString(key) + "\n";
  resultText += "\n";
  resultText += "hmac_key:   " + toHexString(hmac_key) + "\n";

  resultText += "\n";
  resultText += "raw:        " + toHexString(data) + "\n";

  return resultText;
}

function dropHandler(ev) {
  console.debug("File(s) dropped");

  ev.preventDefault();

  if (ev.dataTransfer.items) {
    if (ev.dataTransfer.items[0].kind !== "file") {
      setResultBox("danger", "Dropped item is not a file");
      return;
    }

    var file = ev.dataTransfer.items[0].getAsFile();

    setResultBox(
      "primary",
      "Searching file, please wait\n(this may take a while depending on the file size)"
    );
    findTreasureKeys(file, function (cipherContext, data) {
      console.log(cipherContext);
      if (cipherContext === -1) {
        setResultBox("danger", "Could not find decryption keys");
        return;
      }

      if (data) {
        let resultText = decodeCipherContext(data);
        setResultBox("success", "Found decryption keys:\n" + resultText, true);
        console.log(data);
      }
    });
  }
}

function dragOverHandler(ev) {
  ev.preventDefault();
}
