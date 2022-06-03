const form = document.querySelector(".upload-form"),
form_action =form.getAttribute('action'),
form_method =form.getAttribute('method'),
fileInput = document.querySelector(".file-input"),
progressArea = document.querySelector(".progress-area"),
uploadedArea = document.querySelector(".uploaded-area");
let fd= new FormData(form);

form.addEventListener("click", () =>
{
  fileInput.click();
});

form.addEventListener("dragover", (event)=>
{
    event.preventDefault();
    $('.upload-form').addClass('active');
    $('.upload-header').text('Release to upload');
});

form.addEventListener("dragleave", (event)=>
{
    event.preventDefault();
    $('.upload-form').removeClass('active');
    $('.upload-header').text('File Uploader');
});

form.addEventListener("drop", (event)=>
{
    event.preventDefault();
    $('.upload-header').text('File Uploader');
    $('.upload-form').removeClass('active');
  //getting user select file and [0] this means if user select multiple files then we'll select only the first one
    file = event.dataTransfer.files[0];
    if(file)
    {
        let fileName = file.name;
        if(fileName.length >= 12)
        {
          let splitName = fileName.split('.');
          fileName = splitName[0].substring(0, 13) + "... ." + splitName[1];
        }
        fd.append('media',file)
        uploadFile(fd,fileName);
    }
});


fileInput.onchange = ({target})=>
{
  console.log('changed');
  let file = target.files[0];
  if(file)
  {
    let fileName = file.name;
    if(fileName.length >= 12)
    {
      let splitName = fileName.split('.');
      fileName = splitName[0].substring(0, 13) + "... ." + splitName[1];
    }
    fd.append('media',file)
    uploadFile(fd,fileName);
  }
}
function uploadFile(formdata,name)
{
  let xhr = new XMLHttpRequest();
  xhr.open(form_method, form_action,true);
  xhr.upload.addEventListener("progress", ({loaded, total}) =>
  {
    let fileLoaded = Math.floor((loaded / total) * 100);
    let fileTotal = Math.floor(total / 1000);
    let fileSize;
    (fileTotal < 1024) ? fileSize = fileTotal + " KB" : fileSize = (loaded / (1024*1024)).toFixed(2) + " MB";
    let progressHTML = `<li class="row">
                          <i class="zmdi zmdi-file"></i>
                          <div class="content">
                            <div class="details">
                              <span class="name">${name} • Uploading</span>
                              <span class="percent">${fileLoaded}%</span>
                            </div>
                            <div class="progress-bar">
                              <div class="progress" style="width: ${fileLoaded}%"></div>
                            </div>
                          </div>
                        </li>`;
    uploadedArea.classList.add("onprogress");
    progressArea.innerHTML = progressHTML;
    if(loaded == total)
    {
      progressArea.innerHTML = "";
      let uploadedHTML = `<li class="row">
                            <div class="content upload">
                              <i  class="zmdi zmdi-file"></i>
                              <div class="details">
                                <span class="name">${name} • Uploaded</span>
                                <span class="size">${fileSize}</span>
                              </div>
                            </div>
                            <i class="zmdi zmdi-check"></i>
                          </li>`;
      uploadedArea.classList.remove("onprogress");
      uploadedArea.insertAdjacentHTML("afterbegin", uploadedHTML);
    }
  });
  
  xhr.onreadystatechange=function()
  {
    if(this.readyState == 4 && this.status == 200)
    {
        $('.upload-form')[0].reset();
        $('.small-model').modal({show:true});
        $('.small-model').find('.modal-title').text('Success');
        $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> File uploaded successfully.</div>');
    }
    else
    {
        console.log(this.statusText+':error while uploading file');
    }
  }
  xhr.send(formdata);
}

