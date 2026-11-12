export function FeedItem({ rawMarkup }: { rawMarkup: string }) {
  return <div dangerouslySetInnerHTML={{ __html: rawMarkup }} />;
}
