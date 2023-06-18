//deklaracja express
const express = require('express');
const app = express();
//import mongoose - biblioteki do modelowania obiektów MongoDB(bazy danych) w języku JavaScript
const { mongoose } = require('./database/mongoose');

//body-parser słuzy do analizowania danych przesyłanych w treści zadania HTTP.
const bodyParser = require('body-parser');

//jsonwebtoken uzywany do autoryzacji i uwierzytelniania w aplikacjach sieciowych.
/*JWT(TOKEN) jest wydawany przez serwer po uwierzytelnieniu uzytkownika,
Klient przechowuje token i przekazuje go w nagłówku ządań do serwera przy kazdym kolejnym zadaniu ktore wymaga autoryzacji.
*/
const jwt = require('jsonwebtoken'); 


// Import modeli - modele sluza do definiowania schematow danych, zasad walidacji, operacji na danych i relacji miedzy roznymi encjami.
const { TasksList } = require('./database/models/tasksList.model');
const { Task } = require('./database/models/task.model');
const { User } = require('./database/models/user.model');

//Middleware - są to funkcję pośredniczące, które wykonywane są pomiędzy zadaniem HTTP a obsługą tego zadania przed 'endpoint' aplikacji.
app.use(bodyParser.json());

//autoryzacja tokena - sprawdzanie czy zadanie posiada prawidlowy token dostepu
let authenticate = (req,res,next)=>{
    let token = req.header('x-access-token');
    
    //weryfikacja jsonwebtoken
    jwt.verify(token, User.getJWTSecret(), (err,decoded)=>{
        if (err){
            res.status(401).send(err);  //Jeśli token jest niepoprawny, nie autoryzuj.
        }else{
            req.user_id = decoded._id;
            next();
        }
    })

}

//Weryfikacja Refresh Token ( weryfikacja sesji )
let verify = (req,res,next)=>{
  let refreshToken = req.header('x-refresh-token');
  let _id = req.header('_id');   

  User.findByIdAndToken(_id, refreshToken).then((user)=>{
    if(!user){
        return Promise.reject({
            'error':'Nie znaleziono uzytkownika!'
        });
    }
    //Jesli uzytkownik zostal poprawnie odnaleziony - wykonuje sie ten kod
    //refresh token istnieje w bazie danych, ale musimy sprawdzac czy wygasl czy nie
    req.user_id = user._id;
    req.userObj = user;
    req.refreshToken = refreshToken;

    let sessionIsValid = false;
    user.sessions.forEach((session)=>{
        if (session.token === refreshToken){
            //sprawdzamy czy sesja wygasła
            if (User.hasRefreshTokenExpired(session.expiresAt) === false){
                //to jesli refresh-token nie wygasl.
                sessionIsValid = true;

            }
        }
    }); 
    if (sessionIsValid){
        next();
    }else{
        return Promise.reject({
            'error' : 'refresh token nie jest poprawny!'
        })
    }
  }).catch((e)=>{
    res.status(401).send(e);
  })
};

/*CORS(Cross-Origin Resource Sharing) - to polityka bezpieczeństwa stosowana przez
przeglądarki internetowe, które reguluje, czy i w jaki sposób zasoby na stronie internetowej mogą być 
wymieniane między róznymi domenami(origin).
CORS ma na celu zabezpieczenie przed atakami typu Cross-Site Scripting (XSS) i Cross-Site Request Forgery (CSRF).
Standardowo przeglądarki stosują tzw. "same-origin policy", która uniemożliwia żądania zasobów między różnymi domenami. Oznacza to, że strona internetowa może komunikować się tylko z zasobami z tej samej domeny, protokołu i portu, z którego została załadowana. Jednak w niektórych przypadkach, takich jak wywoływanie żądań API z frontendu na inny serwer, konieczne jest omówienie tej samej polityki.
*/
app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");

    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
});


//ENDPOINT dla List Zadań

//Zwracanie wszystkich list znajdujących się w bazie danych
app.get('/taskslists', authenticate, (req,res)=>{
    TasksList.find({
        _userId: req.user_id
    }).then((taskLists)=>{
        res.send(taskLists);
    }).catch((e)=>{
        res.send(e);
    });
})


//Dodawanie nowej listy do bazy danych
app.post('/taskslists',authenticate,(req,res)=>{
    let listName = req.body.listName;
    let newTasksList = new TasksList({
        listName,
        _userId: req.user_id
    })
    newTasksList.save().then((tasksListDoc)=>{
        res.send(tasksListDoc);
    }) 
})

//Aktualizacja/edycja wybranej listy zadań. (nie działa)
app.patch('/taskslists/:id', authenticate, (req, res) => {
    TasksList.findOneAndUpdate({ 
        _id: req.params.id, 
        _userId: req.user_id 
    },
     {
        $set: req.body
    }).then(() => {
        res.send({ 'message': 'Edytowano liste!'});
    });
});


//Usuwanie wybranej listy z bazy danych
app.delete('/taskslists/:id', authenticate ,(req,res)=>{
    TasksList.findOneAndRemove({
        _id: req.params.id,
        _userId : req.user_id
    }).then((removedTaskListsDoc)=>{
        res.send(removedTaskListsDoc);

        //usuwanie wszystkich zadan ktore sa w danej liscie
        deleteTasksWithList(removedTaskListsDoc._id);
    })
})


//Pobieranie zadań(tasków) nalezących do danej listy
app.get('/taskslists/:listid/tasks', authenticate ,(req,res)=>{
    Task.find({
        _listid: req.params.listid
    }).then((tasks)=>{
        res.send(tasks)
    })
})



//Pokazywanie konkretnego taska (przydatne przy filtrowaniu)
app.get('/taskslists/:listid/tasks/:taskId',authenticate,(req,res)=>{
    Task.findOne({
        _id: req.params.taskId,
        _listid: req.params.listid
    }).then((task)=>{
        res.send(task);
    })
})

//Dodawanie taska/zadania do danej listy ( wybranej )
app.post('/taskslists/:listid/tasks', authenticate ,(req,res)=>{
    
    TasksList.findOne({
        _id: req.params.listid,
        _userId: req.user_id
    }).then((taskslist)=>{
        if (taskslist){
            return true
        }
        return false;
    }).then((canCreateTask)=>{
        if(canCreateTask){
            let newTask = new Task({
        taskName: req.body.taskName,
        _listid: req.params.listid
    });
    newTask.save().then((newTaskDoc)=>{
        res.send(newTaskDoc);
    })
        }else{
            res.sendStatus(404);
        }
    })
    
})


//Edycja taska/zadania w danej liscie
app.patch('/taskslists/:listid/tasks/:taskId', authenticate ,(req,res)=>{
    TasksList.findOne({
        _id: req.params.listid,
        _userId: req.user_id
    }).then((taskslist)=>{
        if (taskslist){
            return true
        }
        return false;
    }).then((canUpdateTasks)=>{
        if(canUpdateTasks){
Task.findOneAndUpdate({
        _id: req.params.taskId,
        _listid: req.params.listid
        },{
        $set: req.body
        }
        ).then(()=>{
        res.send({message: 'Zaktualizowano status!'});//Do zmiany na jakis komunikat!!!
     })
         }else{
            res.sendStatus(404);
         }
    })
    
})


//Usuwanie poszczegolnego taska/zadania z danej listy
app.delete('/taskslists/:listid/tasks/:taskId',authenticate,(req,res)=>{
    TasksList.findOne({
        _id: req.params.listid,
        _userId: req.user_id
    }).then((taskslist)=>{
        if (taskslist){
            return true
        }
        return false;
    }).then((canDeleteTasks)=>{
        if(canDeleteTasks){
            Task.findOneAndRemove({
                _id: req.params.taskId,
                _listid: req.params.listid
             }).then((removedTaskDoc)=>{
                res.send(removedTaskDoc);
            })
        }else{
            res.sendStatus(404);
        }

})
})


//Endpointy dla USERA

/*Rejestracja*/
app.post('/users',(req,res)=>{
    let body = req.body;
    let newUser = new User(body);
    newUser.save().then(()=>{
        return newUser.createSession();
    }).then((refreshToken)=>{
        return newUser.generateAccessToken().then((accessToken)=>{
            return {accessToken,refreshToken}
        });
    }).then((authTokens)=>{
        res
            .header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
        }).catch((e)=>{
            res.status(400).send(e);
        })
})


/*Logowanie*/
app.post('/users/login', (req, res) => {
    let email = req.body.email;
    let password = req.body.password;
    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            // Sesja została utworzona poprawnie - zwrócony refresh token.
            // Teraz generujemy token dostępu (access token) -> pierwszy token dostępu.
            return user.generateAccessToken().then((accessToken) => {
                // access token wygenerowany poprawnie, zwracany jest obiekt który zawiera tokeny
                return { accessToken, refreshToken }
            });
        }).then((authTokens) => {
            // Wysyłamy odpowiedz do uzytkownika z jego tokenami w headerze oraz obiektem uzytkownika w body
            res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})


//GENEROWANIE I ZWRACANIE TOKENU DOSTEPU (ACCESS TOKEN)
app.get('/users/me/access-token', verify, (req,res)=>{
    req.userObj.generateAccessToken().then((accessToken)=>{
        res.header('x-access-token',accessToken).send({accessToken});
    }).catch((e)=>{
        res.status(400).send(e);
    }) 
})



//Funkcja która powoduje usuwanie zadań znajdujących się na liście która jest do usuniecia (nie zostają one w bazie danych)
let deleteTasksWithList = (_listid)=>{
    //zapytanie z mongodb
    Task.deleteMany({
        _listid
    }).then(()=>{
        console.log('Zadania z listy: ' + _listid + ' zostały usunięte!');
    })
}



//ta metoda sluzy do uruchamiania serwera HTTP i nasluchiwania na okreslonym porcie.
//Pozwala aplikacji na nasłuchiwanie przychodzących żądań HTTP i odpowiednie ich obsłużenie.
app.listen(3000, () => {
    console.log("Serwer nasłuchuje na porcie 3000!");
})