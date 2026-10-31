export function renderCommentPreview(rawHtml: string) {
  return `<div dangerouslySetInnerHTML={{ __html: rawHtml }} />`;
}
