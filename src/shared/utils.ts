export function log(...message: any) {
  if (message) {
    let e = document.getElementById("log") as HTMLTextAreaElement | undefined;
    if (e) {
      let text = '';
      for (let m of message) {
        let x: String;
        if (typeof m === 'string' || m instanceof String || typeof m === 'number' || m instanceof Number) {
          x = m+'';
        } else if (m instanceof Error) {
          x = m.message;
        } else {
          x = JSON.stringify(m);
        }
        text += x + ' ';
      }
      text = text.trim().substring(0, 100);
      if (text.length == 100) {
        text += '...';
      }
      e.value += text + '\n';
      e.scrollTo(0, e.scrollHeight);
    }
    console.log(...message);
  }
}

export function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}
