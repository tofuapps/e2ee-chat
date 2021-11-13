import { App } from './App';

const port = process.env.PORT || 8080;
const app = new App(+port);
app.listen();
