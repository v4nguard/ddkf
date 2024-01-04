// const SEARCH_STRING = "GSFARM35011";
const SEARCH_STRING_PS3 = [
  0xff, 0x9f, 0x4c, 0x6b, 0xa7, 0x07, 0x0d, 0xf8, 0x90, 0x89, 0x90, 0xfa, 0xc9,
  0xcd, 0xd0, 0x8c,
];
const STRING_OFFSET_PS3 = 0x01b95150;
const CIPHERCONTEXT_ADDR_PS3 = 0x01b951b0;
const CIPHERCONTEXT_ADDR_RELATIVE_PS3 = CIPHERCONTEXT_ADDR_PS3 - STRING_OFFSET_PS3;

const SEARCH_STRING_X360 = [
  // Offset 0x00000430 to 0x000004BB
  0x40, 0x89, 0x99, 0x9A, 0x40, 0x89, 0x99, 0x9A, 0x40, 0x89, 0x99, 0x9A,
  0x40, 0x89, 0x99, 0x9A, 0x40, 0x89, 0x99, 0x9A, 0x40, 0x89, 0x99, 0x9A,
  0x40, 0x89, 0x99, 0x9A, 0x40, 0x89, 0x99, 0x9A, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x40, 0xAA, 0xC4, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
];

const CIPHERCONTEXT_ADDR_RELATIVE_X360 = 128;

const SEARCH_CHUNK_SIZE = 0x10000;

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

  var platform = document.querySelector('input[name="platform"]:checked').value

  var reader = new FileReader();
  reader.onload = function (e) {
    var data = new Uint8Array(e.target.result);

    if (platform == "ps3") {
      console.log("Using PS3 search string")
      let findRes = findStringInBlock(data, SEARCH_STRING_PS3.slice(0, 10));
      if (findRes !== -1) {
        console.log("Found treasure keys at offset: " + (offset + findRes));
        let cipherContextAddr = offset + findRes + CIPHERCONTEXT_ADDR_RELATIVE_PS3;
        readCipherContext(cipherContextAddr);
        return;
      }
    } else if (platform == "x360") {
      console.log("Using X360 search string")
      let findRes = findStringInBlock(data, SEARCH_STRING_X360.slice(0));
      if (findRes !== -1) {
        console.log("Found treasure keys at offset: " + (offset + findRes));
        let cipherContextAddr = offset + findRes + CIPHERCONTEXT_ADDR_RELATIVE_X360;
        readCipherContext(cipherContextAddr);
        return;
      }
    } else {
      callback(-100);
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
  var resultSpinner = document.getElementById("result-spinner");
  if (type == "process") {
    type = "primary";
    resultSpinner.style.display = "inline-block";
  } else {
    resultSpinner.style.display = "none";
  }

  var resultBox = document.getElementById("result");
  resultBox.classList = "alert alert-" + type;
  if (isCode) {
    resultBox.classList += " font-monospace";
  }

  resultBox.style.display = "block";

  var resultText = document.getElementById("result-text");
  resultText.innerText = text;
}

function toHexString(byteArray) {
  return Array.from(byteArray, function (byte) {
    return ("0" + (byte & 0xff).toString(16)).slice(-2);
  }).join("");
}

function parseCipherContext(data) {
  var dv = new DataView(data.buffer);
  let unk1 = dv.getUint32(0, false);
  let cipher = dv.getUint32(4, false);
  let keylen = dv.getUint32(8, false);

  let key = data.slice(12, 12 + keylen);

  let hmac_key = data.slice(0x24, 0x24 + 16);

  return {
    unk1,
    cipher,
    keylen,
    key,
    hmac_key
  }
}

function decodeCipherContext(data, offset) {
  var resultText = "";

  const platform = document.querySelector('input[name="platform"]:checked').value
  const isXbox = platform == "x360";

  const cipherContext = parseCipherContext(data);

  resultText += "cbc_unk1:   " + "0x" + cipherContext.unk1.toString(16) + "\n";
  resultText += "cbc_cipher: " + cipherContext.cipher + "\n";
  resultText += "cbc_keylen: " + cipherContext.keylen + "\n";
  resultText += "\n";
  resultText += "cbc_key:    " + toHexString(cipherContext.key) + "\n";
  resultText += "hmac_key:   " + toHexString(cipherContext.hmac_key) + "\n";

  resultText += "\n";
  resultText += "raw:        " + toHexString(data) + "\n";

  let isNull = data.every(function (byte) {
    return byte === 0;
  });

  const cipherValid = cipherContext.cipher === 0x1 || (isXbox && cipherContext.cipher === 0x0);

  if (cipherValid && cipherContext.keylen === 0x10) {
    setResultBox(
      "success",
      "Found decryption keys at 0x" + offset.toString(16) + ":\n" + resultText,
      true
    );
  } else if (isNull) {
    setResultBox(
      "warning",
      "Key offset was found (0x" +
      offset.toString(16) +
      "), but the key data is zeroed out!\n\nThis usually means that the memory dump was made before the character select screen.\nIf you believe this is a mistake, please report it to cohae."
    );
  } else {
    setResultBox(
      "danger",
      "Key offset was found (0x" +
      offset.toString(16) +
      "), but data doesn't seem valid\n" +
      resultText,
      true
    );
  }
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
      "process",
      "Searching file, please wait\n(this may take a while depending on the file size)"
    );
    findTreasureKeys(file, function (cipherContext, data) {
      console.log(cipherContext);
      if (cipherContext === -1) {
        setResultBox("danger", "Could not find decryption keys");
        return;
      }
      if (cipherContext === -100) {
        setResultBox("danger", "Invalid platform");
        return;
      }

      if (data) {
        decodeCipherContext(data, cipherContext);
        console.log(data);
      }
    });
  }
}

function dragOverHandler(ev) {
  ev.preventDefault();
}

onload = function () {
  setResultBox("primary", "Waiting for file...", false);
};
