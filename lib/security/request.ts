export type JsonRequestResult =
  | { ok: true; value: unknown }
  | { ok: false; status: 400 | 413 | 415; error: string };

const DEFAULT_MAX_BODY_BYTES = 4 * 1024;

function isJsonContentType(value: string | null): boolean {
  const mediaType = value?.split(";", 1)[0].trim().toLowerCase();
  return mediaType === "application/json" || mediaType?.endsWith("+json") === true;
}

export async function readJsonRequest(
  request: Request,
  maxBytes = DEFAULT_MAX_BODY_BYTES,
): Promise<JsonRequestResult> {
  if (!isJsonContentType(request.headers.get("content-type"))) {
    return { ok: false, status: 415, error: "Content-Type must be application/json." };
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (!Number.isInteger(parsedLength) || parsedLength < 0) {
      return { ok: false, status: 400, error: "Invalid Content-Length header." };
    }
    if (parsedLength > maxBytes) {
      return { ok: false, status: 413, error: `Request body exceeds ${maxBytes} bytes.` };
    }
  }

  if (!request.body) {
    return { ok: false, status: 400, error: "Request body is required." };
  }

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel();
        return { ok: false, status: 413, error: `Request body exceeds ${maxBytes} bytes.` };
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch {
    return { ok: false, status: 400, error: "Could not read request body." };
  }

  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, status: 400, error: "Invalid JSON body." };
  }
}
