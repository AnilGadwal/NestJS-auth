FROM node:16.20

WORKDIR /app
 
COPY package* .

RUN npm i 

COPY . . 

CMD ["npm", "start"]