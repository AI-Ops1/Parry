async function flushQueue(jobs) {
  jobs.forEach(async (job) => {
    await job.commit();
  });
}
module.exports = { flushQueue };
