// Its own module so tests can stand in for the browser's navigation.

/** Opens a URL in this tab; a signed download link saves the file and leaves the page as it is. */
export function openUrl(url: string): void {
  window.location.assign(url);
}
