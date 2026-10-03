import type {FastifyInstance,FastifyListenOptions} from 'fastify';

export async function listenForRuntime(app:FastifyInstance,options:FastifyListenOptions,managed:boolean,
  report:(message:string)=>void=message=>console.error(message)):Promise<void> {
  await app.ready();
  if(managed) {
    // Vercel captures http.Server.listen without invoking its callback/event.
    // Awaiting Fastify's listen promise here prevents module import from finishing.
    void app.listen(options).catch(()=>report('WINDOWS-UNLOCK relay listener failed; inspect the hosting runtime configuration.'));
    return;
  }
  await app.listen(options);
}
