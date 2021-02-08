const arangojs = require("arangojs")
const xmljs = require("xml-js")
const fs = require("fs")
const { collectionToString, Collection } = require("arangojs/collection")
const { isArray } = require("util")

const xmlDoc = fs.readFileSync('..\\699.xml','utf8')
const xmlObj = xmljs.xml2js(xmlDoc, {compact: true, spaces: 4})

const dbName = 'CWE';
const arango_connection_object = {
    url: "http://127.0.0.1:8529",
    auth: {username: "root", password: "xyz"}}

const conn = new arangojs.Database( arango_connection_object );
var openPromises = []

var weaknessesID = {}
var categoriesID = {}
var viewsID = {}

function dropExistingDb(doneCallback) {
    openPromises.push(conn.listDatabases().then(
        (names) => {
        if(names.indexOf(dbName) > -1) {
            console.log('Existing Database to be droped...')
            openPromises.push(conn.dropDatabase(dbName).then(
                () => createDb(doneCallback),
                err => console.error('Failed to drop database:', err)
            ))
        } 
        else {
            createDb(doneCallback)
        }

    }))

}

function createDb(doneCallback) {
    conn.createDatabase(dbName).then(
        () => { 
            console.log('Database created');
            let CWEdb = conn.database(dbName)
            openPromises.push(CWEdb.createCollection("Weaknesses"))
            openPromises.push(CWEdb.createCollection("Categories"))
            openPromises.push(CWEdb.createCollection("Views"))
            openPromises.push(CWEdb.createCollection("ExternalReferences"))

            openPromises.push(CWEdb.createEdgeCollection("HasMemberEdge"))
            openPromises.push(CWEdb.createEdgeCollection("ChildOfEdge"))
            openPromises.push(CWEdb.createEdgeCollection("ExternalReferenceEdge"))
            Promise.allSettled(openPromises).then(() => {openPromises=[]; writeWeaknesses(CWEdb, doneCallback)})
        },
        err => console.error('Failed to create database:', err)
    );
}

function useDb(doneCallback) {
    let CWEdb = conn.database(dbName)
    writeWeaknesses(CWEdb, doneCallback);
}

function checkAndWrite(element, collection, ID) {
    return new Promise((resolve, reject) => {
        collection.documentExists(ID).then(
            exists => {if(!(exists)) {
                element._key = ID;
                collection.save(element).then(
                    meta => { resolve(meta)},
                    err => { reject(err)}
                )
            }
            }
        )
    })
}

function writeWeaknesses(CWEdb, doneCallback) {
    const weaknessCol = CWEdb.collection("Weaknesses")
    // If only one Weakness exists it is converted into an object, we make it an array so we save to treat this case seperately
    if(!Array.isArray(xmlObj.Weakness_Catalog.Weaknesses.Weakness)) {
        xmlObj.Weakness_Catalog.Weaknesses.Weakness = [xmlObj.Weakness_Catalog.Weaknesses.Weakness];
    }
    xmlObj.Weakness_Catalog.Weaknesses.Weakness.forEach(
        weakness => {
            openPromises.push(checkAndWrite(weakness,weaknessCol, weakness._attributes.ID)
                                .then((meta)=>{ console.log('Weakness ' + weakness._key + " save: " + meta._rev); weaknessesID[weakness._attributes.ID]=meta._id })
                                .catch((err) => console.log("Falied to save:", err) )
            )}
    )
    writeCategories(CWEdb, doneCallback);
}

function writeCategories(CWEdb, doneCallback) {
    const categoryCol = CWEdb.collection("Categories")
    // If only one Categories exists it is converted into an object, we make it an array so we save to treat this case seperately
    if(!Array.isArray(xmlObj.Weakness_Catalog.Categories.Category)) {
        xmlObj.Weakness_Catalog.Categories.Category = [xmlObj.Weakness_Catalog.Categories.Category]
    }
    xmlObj.Weakness_Catalog.Categories.Category.forEach(
        category => {
        openPromises.push( checkAndWrite(category, categoryCol, category._attributes.ID)
                                .then(meta => {console.log('Category ' + category._key + " save: " + meta._rev); categoriesID[category._attributes.ID]=meta._id })
                                .catch(err => console.log("Falied to save:", err))
            )}
        )

    writeViews(CWEdb, doneCallback);
}

function writeViews(CWEdb, doneCallback) {
    const viewCol = CWEdb.collection("Views")
    // If only one views exists it is converted into an object, we make it an array so we save to treat this case seperately
    if(!Array.isArray(xmlObj.Weakness_Catalog.Views.View)) {
        xmlObj.Weakness_Catalog.Views.View = [xmlObj.Weakness_Catalog.Views.View]
    }
    xmlObj.Weakness_Catalog.Views.View.forEach(
        view => {
            openPromises.push( checkAndWrite(view,viewCol, view._attributes.ID)
                                .then(meta => {console.log('View ' + view._key + " save: " + meta._rev); viewsID[view._attributes.ID]=meta._ID})
                                .catch(err => console.log("Falied to save:", err))                                
            )}
    )
    writeExternalReferences(CWEdb, doneCallback);
} 

function writeExternalReferences(CWEdb, doneCallback) {
    const referenceCol = CWEdb.collection("ExternalReferences")
    // If only one External_Reference exists it is converted into an object, we make it an array so we save to treat this case seperately
    if(!Array.isArray(xmlObj.Weakness_Catalog.External_References.External_Reference)) {
        xmlObj.Weakness_Catalog.External_References.External_Reference = [xmlObj.Weakness_Catalog.External_References.External_Reference]
    }
    xmlObj.Weakness_Catalog.External_References.External_Reference.forEach(
        reference => {
        openPromises.push(checkAndWrite(reference,referenceCol, reference._attributes.Reference_ID)
                            .then(meta => {console.log('reference ' + reference._key + " save: " + meta._rev)})
                            .catch(err => console.log("Falied to save:", err))
                    )}
    )

    Promise.all(openPromises).then(() => {openPromises = [] ; doneCallback()})
}

function installConnections() {
    let CWEdb = conn.database(dbName)
    const weaknessCol = CWEdb.collection("Weaknesses")
    const weaknessEdgeCol = CWEdb.collection("WeaknessesEdge")
    openPromises.push(CWEdb.query(`FOR doc IN Weaknesses RETURN doc`).then(
            cursor => {
                cursor.all().then(
                    allElements => { 
                        allElements.forEach(
                            element => importElementConnections(element)
                        )

                    }
                )
            }
        )
    )        
}

function importElementConnections(element) {

}



dropExistingDb(installConnections);
//useDb();

