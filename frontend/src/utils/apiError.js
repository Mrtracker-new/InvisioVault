/**
 * Extract the server's error message from an Axios error.
 *
 * Requests made with `responseType: 'blob'` receive the ERROR body as a
 * Blob too, so `err.response.data.error` is always undefined on those
 * endpoints — the Blob must be read as text and parsed as JSON first.
 * Plain JSON error responses are handled as before.
 *
 * @param {unknown} err      Axios error (or anything thrown)
 * @param {string}  fallback Message to use when no server message is found
 * @returns {Promise<string>}
 */
export async function getApiErrorMessage(err, fallback) {
  const data = err?.response?.data

  if (data instanceof Blob) {
    try {
      const json = JSON.parse(await data.text())
      return json.error || fallback
    } catch {
      return fallback
    }
  }

  return data?.error || fallback
}
