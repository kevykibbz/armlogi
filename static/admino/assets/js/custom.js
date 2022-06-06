
/*insection observer API */
function observerImages()
{
    var images=document.querySelectorAll('[data-src]'),
    imgOpts={},
    observer=new IntersectionObserver((entries,observer)=>
    {
        entries.forEach((entry)=>
        {
            if(!entry.isIntersecting) return;
            const img=entry.target;
            const newUrl=img.getAttribute('data-src');
            img.src=newUrl;
            observer.unobserve(img);
        });
    },imgOpts);
  
    images.forEach((image)=>
    {
      observer.observe(image)
    });
}

$(document).ready(function()
{
  observerImages();
  var b=$('body').attr('class').split(' '),
  c=$(b).get(-1);
  if(c == 'ls-closed')
  {
      $('.user-pallate').addClass('user-area');
  }
});

$(document).on('click','.ls-toggle-btn',function()
{
    var b=$('body').attr('class').split(' '),
    c=$(b).get(-1);
    if(c !== 'ls-toggle-menu')
    {
        $('.user-pallate').removeClass('user-area');
    }
    else
    {
        $('.user-pallate').addClass('user-area');
    }
});

$(document).on('click','.btn-remove',function()
{
  $(this).parent().find('.loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $(this).parent().hide(); 
  return false;                                                
});

$(document).on('click','.getprofilepic',function()
{
    var el=$(this);
    el.parents('.card').find('.load-overlay').show();
    el.parents('.card').find('.overlay-close').removeClass('btn-remove');
    $('#id_profile_pic').click();
});

$(document).on('change','.profile',function()
{
    var el=$(this),
    file=el.get(0).files[0],
    ext=el.val().substring(el.val().lastIndexOf('.')+1).toLowerCase();
    $('.imagecard').find('.overlay-close').addClass('btn-remove');
    $('.imagecard').find('.load-overlay').hide();
    if(file && (ext=='jpg' || ext=='png' || ext=='jpeg' || ext=='gif'))
    {
        var reader=new FileReader();
        reader.onload=function(e)
        {
            $('.imagecard').find('img').attr('src',reader.result);
        }
        reader.readAsDataURL(file);
    }
    else
    {
      $('.small-model').modal({show:true});
      $('.small-model').find('.modal-title').text('Warning');
      $('.small-model').find('.modal-body').html('<div class="text-warning text-center"><i class="zmdi zmdi-alert-triangle"></i> Invalid image format</div>');
    }
});

/*submit register form*/
$(document).on('submit','.regForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:last').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> User  saved successfully.</div>');
            if(typeof callback.profile_pic !==undefined && callback.profile_pic.length)
            {
              $(document).find('.user-image').attr('src',callback.profile_pic);
            }
            window.location='/view/users/';
        }
        else
        {
            $.each(callback.uform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
            $.each(callback.eform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});

/*submit register form*/
$(document).on('submit','.regForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:last').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> User  saved successfully.</div>');
            if(typeof callback.profile_pic !==undefined && callback.profile_pic.length)
            {
              window.location=window.location;
            }
            window.location='/view/users/';
        }
        else
        {
            $.each(callback.uform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
            $.each(callback.eform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});

/*submit profile form*/
$(document).on('submit','.profForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:last').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> User  saved successfully.</div>');
            window.location=window.location;
        }
        else
        {
            $.each(callback.uform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
            $.each(callback.eform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:last').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});

/*profile pic*/
$(document).on('submit','.profileForm',function()
{
    var el=$(this),
    form_data=new FormData(this);
    el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
    $.ajax(
    {
        url:el.attr('action'),
        method:el.attr('method'),
        dataType:'json',
        data:form_data,
        contentType:false,
        cache:false,
        processData:false,
        beforeSend:function()
        {
          el.parents('.card').find('.load-overlay').show();
          el.find('button:last').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
          el.find('button:last').text(' Please wait...');
          el.find('button').attr('disabled',true);
          el.parents('.card').find('.overlay-close').removeClass('btn-remove');
        },
        success:function(callback)
        {
            el.parents('.card').find('.overlay-close').addClass('btn-remove');
            el.parents('.card').find('.load-overlay').hide();
            el.find('button:last').html('');
            el.find('button:last').text('Choose picture');
            el.find('button').attr('disabled',false);
            if(callback.valid)
            {
              el.parents('.tab-pane').find('.load-overlay').show();
              el.parents('.tab-pane').find('.load-overlay .loader-container').html('<span class="text-success font-weight-bold"><i class="fa fa-check-circle"></i> '+callback.message+'</span>.');
              refreshPage(el,el.data('host'),'edit-wall');
            }
            else
            {
                
            }
        },
        error:function(err)
        {
          el.parents('.card').find('.overlay-close').addClass('btn-remove');
          el.parents('.card').find('.load-overlay').hide();
          el.find('button:last').html('Choose picture');
          el.find('button:last').text('upload');
          el.find('button').attr('disabled',false);
        }
    }
    );
return false;
});


$(document).on('click','.del-data',function(e)
{
  e.preventDefault();
  var el=$(this);
  $('.delete-model').modal({show:true});
  $('.delete-model').find('.modal-title').text('Confirm');
  $('.delete-model').find('.modal-body').html('<div class="text-warning text-info text-center"><i class="zmdi zmdi-alert-triangle"></i> Confirm deleting item .</div> <div class="text-center"><button class="btn btn-secondary cancelBtn" >cancel</button><button data-host="'+el.data('host')+'" data-url="'+el.attr('href')+'" class="btn btn-danger confirmBtn">confirm</button></div>');
});

$(document).on('click','.del-data2',function(e)
{
  e.preventDefault();
  var el=$(this);
  $('.delete-model').modal({show:true});
  $('.delete-model').find('.modal-title').text('Confirm');
  $('.delete-model').find('.modal-body').html('<div class="text-warning text-info text-center"><i class="zmdi zmdi-alert-triangle"></i> Confirm deleting item .</div> <div class="text-center"><button class="btn btn-secondary cancelBtn" >cancel</button><button data-host="'+el.data('host')+'" data-url="'+el.attr('href')+'" class="btn btn-danger confirmBtn2">confirm</button></div>');
});

$(document).on('click','.del-data3',function(e)
{
  e.preventDefault();
  var el=$(this);
  $('.delete-model').modal({show:true});
  $('.delete-model').find('.modal-title').text('Confirm');
  $('.delete-model').find('.modal-body').html('<div class="text-warning text-info text-center"><i class="zmdi zmdi-alert-triangle"></i> Confirm deleting item .</div> <div class="text-center"><button class="btn btn-secondary cancelBtn" >cancel</button><button data-host="'+el.data('host')+'" data-url="'+el.attr('href')+'" class="btn btn-danger confirmBtn3">confirm</button></div>');
});


$(document).on('click','.cancelBtn',function()
{
  $(this).parents('.modal').find('.close').click();
});

$(document).on('click','.confirmBtn',function()
{
  var el=$(this),
  url=el.data('url');
  $.ajax(
      {
        url:url,
        dataType:'json',
        beforeSend:function()
        {
          el.html('<i class="spinner-border spinner-border-sm" role="status"></i> Please wait...');
        },
        success:function(callback)
        {
          el.html('confirm');
          refreshPage(el,el.data('host'),'table-results');
          $('.delete-model').modal('hide');
          $('.small-model').modal('show');
          $('.small-model').find('.modal-title').text('Success');
          $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Item deleted successfully.</div>');
        },
        error(err)
        {
          el.html('confirm');
          console.log(err.status+':'+err.statusText);
        }
      });
});

$(document).on('click','.confirmBtn2',function()
{
  var el=$(this),
  url=el.data('url');
  $.ajax(
      {
        url:url,
        dataType:'json',
        beforeSend:function()
        {
          el.html('<i class="spinner-border spinner-border-sm" role="status"></i> Please wait...');
        },
        success:function(callback)
        {
          el.html('confirm');
          $('.delete-model').modal('hide');
          $('.small-model').modal('show');
          $('.small-model').find('.modal-title').text('Success');
          $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Item deleted successfully.</div>');
          window.location=window.location;
        },
        error(err)
        {
          el.html('confirm');
          console.log(err.status+':'+err.statusText);
        }
      });
});

$(document).on('click','.confirmBtn3',function()
{
  var el=$(this),
  url=el.data('url');
  $.ajax(
      {
        url:url,
        dataType:'json',
        beforeSend:function()
        {
          el.html('<i class="spinner-border spinner-border-sm" role="status"></i> Please wait...');
        },
        success:function(callback)
        {
          el.html('confirm');
          $('.delete-model').modal('hide');
          $('.small-model').modal('show');
          $('.small-model').find('.modal-title').text('Success');
          $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Logs deleted successfully.</div>');
          window.location=window.location;
        },
        error(err)
        {
          el.html('confirm');
          console.log(err.status+':'+err.statusText);
        }
      });
});
/*refreshPage*/
function refreshPage(wrapper,url, target)
{
    $.ajax(
    {
      url:url,
      context:this,
      dataType:'html',
      success:function(callback)
      {
        $(document).find('.'+target).html($(callback).find('.'+target).html());
        observerImages();
      },
      error:function(err)
      {
        console.log(err.status+':'+err.statusText);
      }
    });
}

/*editorderbtn*/
$(document).on('click','.editorderbtn',function()
{
  var el=$(this),
  url=el.attr('href'),
  content=el.parents('.card').find('.card-contenter').text();
  $(document).find('#editModal form').attr('action',url);
  $(document).find('#editModal form input:last').val(content);
});

/*submit password form*/
$(document).on('submit','.passForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:first').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Password  changed successfully.</div>');
        }
        else
        {
            $.each(callback.passform_errors,function(key,value)
            {
                el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});


/*submit password form*/
$(document).on('submit','.myForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:first').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Data saved successfully.</div>');
            refreshPage(el,el.data('host'),'table-results');
          }
        else
        {
            $.each(callback.form_errors,function(key,value)
            {
                el.find("input[name='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});


$(document).on('mouseenter','.order-wrapper',function()
{
  $(this).find('.buttons').show();
});
$(document).on('mouseleave','.order-wrapper',function()
{
  $(this).find('.buttons').hide();
});


/*spreadsheetForm*/
$(document).on('submit','.spreadsheetForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:last ').text(' Saving...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Data saved successfully.</div>');
           window.location='/order/summary/';
        }
        else
        {
            $.each(callback.form_errors,function(key,value)
            {
              el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
        if(callback.error)
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Info');
            $('.small-model').find('.modal-body').html('<div class="text-info text-center"><i class="fa fa-exclamation-triangle"></i> No changes made.</div>');
          }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});

/*spreadsheetForm*/
$(document).on('submit','.CustomerForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:first').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Data saved successfully.</div>');
           window.location='/customer/quote/';
          }
        else
        {
            $.each(callback.form_errors,function(key,value)
            {
              el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});

/*spreadsheetForm*/
$(document).on('submit','.CustomerEditForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:first').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        if(callback.valid)
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Data saved successfully.</div>');
           window.location='/do/incomings/';
          }
        else
        {
            $.each(callback.form_errors,function(key,value)
            {
              el.find("input[aria-label='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});


/*submit password form*/
$(document).on('submit','.orderForm',function()
{
  var el=$(this),
  form_data=new FormData(this);
  $('.feedback').html('');
  el.children().find('.is-invalid').removeClass('is-invalid');
  el.parents('.card').find('.load-overlay .loader-container').html(`<div class="innerloader"><svg class="circular" viewBox="25 25 50 50"><circle class="path" cx="50" cy="50" r="10" fill="none" stroke-width="2" stroke-miterlimit="10"/></svg></div>`);
  $.ajax(
    {
      url:el.attr('action'),
      method:el.attr('method'),
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.parents('.card').find('.load-overlay').show();
        el.find('button:first').html('<i class="spinner-border spinner-border-sm" role="status"></i>');
        el.find('button:last').text(' Please wait...');
        el.find('button').attr('disabled',true);
        el.parents('.card').find('.overlay-close').removeClass('btn-remove');
      },
      success:function(callback)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.parents('.card').find('.load-overlay').hide();
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        console.log(callback);
        if(callback.valid)
        {
            el[0].reset();
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Data saved successfully.</div>');
            window.location='/tabulate/order/'+callback.order_id+'/';
          }
        else
        {
            $.each(callback.form_errors,function(key,value)
            {
                el.find("input[name='"+key+"']").addClass('is-invalid').parents('.form-group').find('.feedback').addClass('invalid-feedback').html('<i class="fa fa-exclamation-circle"></i> '+value);
            });
        }
      },
      error:function(err)
      {
        el.parents('.card').find('.overlay-close').addClass('btn-remove');
        el.find('button:first').html('');
        el.find('button:last').text('Save changes');
        el.find('button').attr('disabled',false);
        el.parents('.card').find('.load-overlay .loader-container').html('<span class="text-danger font-weight-bold"> <i class="zmdi zmdi-alert-triangle"></i> '+err.status+' :'+err.statusText+'</span>.');
      }
    });
  return false;
});


$(document).on('click','.status-field',function()
{
    $('.select-model').modal('show');
});

$(document).on('change','#id_stats',function()
{
    var selected_item=$('#id_stats').val();
    $('.status-field').val(selected_item);
    $('.select-model').modal('hide');
});

$(document).on('change','input[type=file]',function()
{
  $(this).removeClass('is-invalid').addClass('is-valid').parent().find('.feedback').removeClass('invalid-feedback').addClass('valid-feedback').html('Filename: '+this.files[0].name);
});


/*send_notification*/
$(document).on('click','.send_notification',function()
{
  var el=$(this),
  form_data=new FormData();
  form_data.append('id',el.data('id'));
    $.ajax(
    {
      url:el.data('url'),
      method:'post',
      dataType:'json',
      data:form_data,
      contentType:false,
      cache:false,
      processData:false,
      beforeSend:function()
      {
        el.text('Please wait...');
        el.attr('disabled',true);
      },
      success:function(callback)
      {
        el.text('Send notification');
        el.attr('disabled',false);
        if(callback.valid)
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Success');
            $('.small-model').find('.modal-body').html('<div class="text-success text-center"><i class="fa fa-check-circle"></i> Notification sent successfully.</div>');
            //window.location='/tabulate/order/'+callback.order_id+'/';
        }
        else
        {
            $('.small-model').modal({show:true});
            $('.small-model').find('.modal-title').text('Error');
            $('.small-model').find('.modal-body').html('<div class="text-danger text-center"><i class="fa fa-exclamation-circle"></i> '+callback.message+'</div>');
        }
      },
      error:function(err)
      {
        el.text('Send notification');
        el.attr('disabled',false);
      }
    });
});