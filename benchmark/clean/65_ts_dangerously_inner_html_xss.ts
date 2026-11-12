import DOMPurify from 'dompurify';
export function FeedItem({ rawMarkup }: { rawMarkup: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(rawMarkup) }} />;
}
